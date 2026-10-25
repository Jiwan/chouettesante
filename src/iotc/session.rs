// The session data shared by every connection state: identity,
// credentials, the per-peer table, and the parsed facts the state
// machines consume.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Instant,
};

use openssl::{
    ec::EcKey,
    pkey::{PKey, Public},
};

use anyhow::Result;
use tracing::{debug, warn};

use super::{
    crypto::{derive_aes_128_key, generate_ecdh_key},
    wire::ServerEntry,
};

// Mirrors the per-server state in the Session server table (state byte at
// +0x7e7) in libIOTCAPIs.so: one machine per server peer, tracking how the
// rendezvous with the device progresses through that particular server.
#[derive(Debug, PartialEq)]
pub(super) enum PeerState {
    AwaitingHandshakeResp,
    // The server reported the device as not connected there (cmd 0x227).
    DeviceReportedOffline,
    // The server reported the device as connected there (cmd 0x229).
    DeviceReportedOnline,
    // The type 3 handshake response was accepted: this peer carries the
    // session from now on.
    Connected {
        record_sid: u32,
        keepalive_interval: u16,
        last_alive: Instant,
    },
}

pub(super) struct P2PPeer {
    pub(super) aes_key: [u8; 16],
    pub(super) aes_iv: [u8; 12],
    pub(super) state: PeerState,
}

#[derive(Debug)]
pub enum ParseOutcome {
    ServerList(Vec<ServerEntry>),
    HandshakeResp {
        record_sid: u32,
        keepalive_interval: u16,
    },
    KeepAlive {
        record_sid: u32,
    },
    DeviceStatus {
        online: bool,
        uid: [u8; 20],
    },
    HelloClient {
        address: SocketAddr,
    },
    Packet,
    Other,
}

// Shared session data, owned by all states. Sort off mirror Session in libIOTCAPIs.so.
pub struct SessionCore {
    pub(super) session_id: u32,
    pub(super) device_id: [u8; 20],
    pub(super) aes_key: [u8; 16],
    pub(super) aes_iv: [u8; 12],
    pub(super) nonce1: u16,
    pub(super) nonce2: u16,
    pub(super) ecdh_key: EcKey<openssl::pkey::Private>,
    // From UIDExtraData/field_0x11ac in libIOTCAPIs.so: the 8-byte auth key
    // (camera-kms auth_key) carried in the P2PInit packet content.
    pub(super) auth_key: [u8; 8],
    // Mirrors Session.peers[0..0xb] in libIOTCAPIs.so: one set of P2P
    // credentials per server address.
    pub(super) peers: HashMap<SocketAddr, P2PPeer>,
    // Our public address as seen by the P2P servers, from addNatRecord.
    pub(super) public_address: Option<SocketAddr>,
}

impl SessionCore {
    pub(super) fn new(session_id: u32, uid: &str, auth_key: [u8; 8]) -> Self {
        // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so: the uid is
        // normalized to uppercase (chars > 'Z' get 0x20 subtracted) before
        // use, matching how the device registers itself with the P2P
        // servers.
        let device_id: String = uid.to_uppercase();
        let nonce1 = rand::random::<u16>();
        let nonce2 = rand::random::<u16>();

        let mut aes_key: [u8; 16] = [0; 16];
        rand::fill(&mut aes_key);

        let mut aes_iv: [u8; 12] = [0; 12];
        rand::fill(&mut aes_iv);

        Self {
            session_id,
            device_id: device_id.as_bytes().try_into().unwrap(),
            aes_key,
            aes_iv,
            nonce1,
            nonce2,
            ecdh_key: generate_ecdh_key().unwrap(),
            auth_key,
            peers: HashMap::new(),
            public_address: None,
        }
    }

    // Mirrors iotcGetP2PKeyInfo/iotcUpdateP2PAESKeys in libIOTCAPIs.so: the
    // peer AES key is derived from the ECDH shared secret with that peer's
    // public key and the IV is freshly randomized per peer, both cached by
    // server address.
    pub(super) fn get_or_create_peer(
        &mut self,
        address: &SocketAddr,
        peer_pub_key: &PKey<Public>,
    ) -> Result<&P2PPeer> {
        if !self.peers.contains_key(address) {
            let aes_key = derive_aes_128_key(&self.ecdh_key, peer_pub_key)?;
            let mut aes_iv = [0u8; 12];
            rand::fill(&mut aes_iv);
            self.peers.insert(
                *address,
                P2PPeer {
                    aes_key,
                    aes_iv,
                    state: PeerState::AwaitingHandshakeResp,
                },
            );
        }

        Ok(self.peers.get(address).unwrap())
    }

    fn peer_mut(&mut self, address: &SocketAddr) -> Option<&mut P2PPeer> {
        self.peers.get_mut(address)
    }

    // Applies a parsed wire fact to the per-peer state machines. The main
    // machine transitions are handled by the states' on_datagram.
    pub(super) fn apply_peer_outcome(&mut self, outcome: &ParseOutcome, from: SocketAddr) {
        match outcome {
            ParseOutcome::HandshakeResp {
                record_sid,
                keepalive_interval,
            } => {
                if let Some(peer) = self.peer_mut(&from) {
                    peer.state = PeerState::Connected {
                        record_sid: *record_sid,
                        keepalive_interval: *keepalive_interval,
                        last_alive: Instant::now(),
                    };
                    debug!("Peer {} promoted to Connected", from);
                } else {
                    warn!("Handshake response from an unknown peer: {}", from);
                }
            }
            ParseOutcome::KeepAlive { record_sid } => {
                if let Some(peer) = self.peer_mut(&from) {
                    match &mut peer.state {
                        PeerState::Connected {
                            record_sid: expected,
                            last_alive,
                            ..
                        } if *expected == *record_sid => {
                            *last_alive = Instant::now();
                        }
                        PeerState::Connected { .. } => {
                            warn!("Keepalive from {} with a wrong record sid", from);
                        }
                        _ => {
                            warn!("Keepalive from {} before the handshake completed", from);
                        }
                    }
                }
            }
            ParseOutcome::DeviceStatus { online, uid } => {
                if uid == &self.device_id {
                    if let Some(peer) = self.peer_mut(&from) {
                        if !matches!(peer.state, PeerState::Connected { .. }) {
                            peer.state = if *online {
                                PeerState::DeviceReportedOnline
                            } else {
                                PeerState::DeviceReportedOffline
                            };
                        }
                    }
                } else {
                    debug!("Device status for another device: {:?}", uid);
                }
            }
            ParseOutcome::HelloClient { address } => {
                // From addNatRecord in libIOTCAPIs.so: our public address as
                // seen by the server.
                debug!("Client public address: {}", address);
                self.public_address = Some(*address);
            }
            _ => {}
        }
    }

    // Whether every known peer reports the device as offline there.
    pub(super) fn device_offline_everywhere(&self) -> bool {
        !self.peers.is_empty()
            && self
                .peers
                .values()
                .all(|p| matches!(p.state, PeerState::DeviceReportedOffline))
    }
}


// Master rendezvous: regions and the master domain names.

#[cfg(test)]
pub(super) fn test_public_key() -> Result<PKey<Public>> {
    let key = generate_ecdh_key()?;
    let der = key.public_key_to_der()?;
    Ok(PKey::public_key_from_der(&der)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{io::Cursor, net::Ipv4Addr};

    use crate::{
        charlie_cypher,
        iotc::{constants::PACKET_HEADER_SIZE, wire::*},
        utils::BinaryWriter,
    };

    #[test]
    fn p2p_peer_credentials_are_cached_per_server_address() {
        let mut session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");

        let addr_a = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 1111));
        let pub_a = test_public_key().unwrap();
        let peer_a = session.get_or_create_peer(&addr_a, &pub_a).unwrap();
        let (key_a, iv_a) = (peer_a.aes_key, peer_a.aes_iv);

        // A second handshake to the same server reuses the cached
        // credentials instead of re-deriving them.
        let peer_a_again = session.get_or_create_peer(&addr_a, &pub_a).unwrap();
        assert_eq!(key_a, peer_a_again.aes_key);
        assert_eq!(iv_a, peer_a_again.aes_iv);

        // A different server gets its own key and a fresh IV.
        let addr_b = SocketAddr::from((Ipv4Addr::new(5, 6, 7, 8), 2222));
        let pub_b = test_public_key().unwrap();
        let peer_b = session.get_or_create_peer(&addr_b, &pub_b).unwrap();
        assert_ne!(key_a, peer_b.aes_key);
        assert_ne!(iv_a, peer_b.aes_iv);
    }

    #[test]
    fn device_status_packet_flips_the_peer_state() {
        let mut session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");
        let addr = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 1111));
        let pub_key = test_public_key().unwrap();
        session.get_or_create_peer(&addr, &pub_key).unwrap();

        // A cmd 0x227 packet as the servers send it: the whole datagram
        // charlie-cyphered, content = the 20-byte device uid.
        let mut packet = vec![0u8; PACKET_HEADER_SIZE + 20];
        let mut writer = Cursor::new(packet.as_mut_slice());
        write_packet(
            &mut writer,
            PacketHeader {
                command: CmdType::DeviceOfflineStatus as u16,
                channel_id: 0,
                flags: PacketFlags::empty(),
                command_options: 0,
                session_id: 0,
                channel_flags: 0,
                content_size: 20,
            },
            |writer| {
                writer.write_bytes(&session.device_id)?;
                Ok(())
            },
            20,
        )
        .unwrap();
        charlie_cypher::cypher(&mut packet);

        let outcome = parse_packet(&packet, PacketCypher::Charlie).unwrap();
        let PacketOutcome::DeviceStatus { online, uid } = outcome else {
            panic!("Expected a DeviceStatus outcome");
        };
        assert!(!online);
        assert_eq!(uid, session.device_id);

        // The peer machine applies the fact; the main machine is not
        // affected by a device status.
        session.apply_peer_outcome(
            &ParseOutcome::DeviceStatus {
                online: false,
                uid: session.device_id,
            },
            addr,
        );
        assert_eq!(session.peers[&addr].state, PeerState::DeviceReportedOffline);
        assert!(session.device_offline_everywhere());
    }

}
