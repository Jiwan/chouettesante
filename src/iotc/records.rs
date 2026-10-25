// The record layer: crafting the outgoing records and parsing the
// incoming ones, one helper per message. The send side crafts last
// minute from the session; the receive side is a pure parse producing
// ParseOutcome facts for the state machines to apply.

use std::{io::Cursor, net::SocketAddr};

use anyhow::{Context, Result, bail};
use tracing::{debug, warn};

use super::{
    constants,
    get_realm,
    session::{P2PPeer, ParseOutcome, SessionCore},
    wire::{
        CmdType, PacketCypher, PacketHeader, PacketOutcome, ParseError, RecordDecryption,
        RecordEncryption, RecordType, ServerEntry, parse_packet, read_record_header_and_decrypt,
        write_packet, write_record,
    },
};

use crate::{
    charlie_cypher, iotc::wire::PacketFlags, utils::{BinaryReader, BinaryWriter},
};

pub(super) fn make_record_send_master_handshake(session: &SessionCore) -> Result<Vec<u8>> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    const RECORD_SIZE: usize = 0x100;
    const EXPECTED_PACKET_SIZE: usize = 0x58;
    const EXPECTED_CONTENT_SIZE: usize = 0x48;

    write_record(
        RecordType::MasterHandshake,
        session.session_id,
        RECORD_SIZE,
        EXPECTED_PACKET_SIZE,
        RecordEncryption::Rsa,
        |_| Ok(()),
        |writer| {
            write_packet(
                writer,
                PacketHeader {
                    command: CmdType::P2PInitHandshakeReq as u16,
                    channel_id: 0,
                    flags: PacketFlags::empty(),
                    command_options: 0x18,
                    session_id: 0,
                    channel_flags: 0,
                    content_size: EXPECTED_CONTENT_SIZE as u16,
                },
                |writer| {
                    writer.write_le_u16(session.nonce1)?;
                    writer.write_le_u16(0)?;
                    writer.write_bytes(&session.aes_key)?;
                    writer.write_bytes(&session.aes_iv)?;
                    writer.write_bytes(&session.device_id)?;
                    writer.write_bytes(&get_realm().as_bytes()[0..0x10])?;
                    writer.write_u8(0x6)?;
                    writer.write_u8((session.session_id == 0xffff) as u8)?;
                    writer.write_le_u16(0)?;
                    Ok(())
                },
                EXPECTED_CONTENT_SIZE,
            )
        },
    )
}

fn make_p2p_init_packet(
    packet_writer: &mut Cursor<&mut [u8]>,
    session: &SessionCore,
) -> Result<()> {
    const EXPECTED_CONTENT_SIZE: usize = 0x24;

    write_packet(
        packet_writer,
        PacketHeader {
            command: CmdType::P2PInit as u16,
            channel_id: 0,
            flags: PacketFlags::empty(),
            command_options: 0x24,
            session_id: 0,
            channel_flags: 0,
            content_size: EXPECTED_CONTENT_SIZE as u16,
        },
        |writer| {
            // From iotcRecordSendP2PInitHandshakeReq (0x217 mode) in
            // libIOTCAPIs.so, with client_params = the session: the nonce2 is
            // checked against the P2PInitHandshakeResp, then comes the
            // device uid, then p2p_config fields that are zeroed in the
            // AddUDPPreCheckTask path.
            writer.write_le_u16(session.nonce2)?;
            writer.write_le_u16(0)?;
            writer.write_bytes(&session.device_id)?;
            writer.write_le_u32(0)?; // *(undefined4 *)(p2p_config + 2)
            // *(undefined8 *)*(byte **)(p2p_config + 4): 8 bytes from
            // session->field_0x11ac, filled from the UIDExtraData auth key
            // the app passes to IOTC_Connect_ByUIDEx (connectWithAuth in the
            // Owlet CameraSDK): the camera-kms auth_key.
            writer.write_bytes(&session.auth_key)?;
            Ok(())
        },
        EXPECTED_CONTENT_SIZE,
    )
}

pub(super) fn make_record_send_p2p_init_handshake_req(
    session: &mut SessionCore,
    server_entry: &ServerEntry,
) -> Result<Vec<u8>> {
    // From iotcRecordSendP2PInitHandshakeReq in libIOTCAPIs.so.
    const RECORD_SIZE: usize = 0xac;
    const EXPECTED_PACKET_SIZE: usize = 0x34;

    let peer_address = SocketAddr::from((server_entry.ip_address, server_entry.port));
    let P2PPeer {
        aes_key, aes_iv, ..
    } = *session.get_or_create_peer(&peer_address, &server_entry.pub_key)?;

    let der = session.ecdh_key.public_key_to_der()?;
    assert_eq!(der.len(), 0x5b, "ECDH DER key must be exactly 0x5B bytes");

    write_record(
        RecordType::P2PInitHandshakeReq,
        session.session_id,
        RECORD_SIZE,
        EXPECTED_PACKET_SIZE,
        RecordEncryption::Aes128Gcm {
            key: aes_key,
            iv: aes_iv,
        },
        move |writer| {
            writer.write_bytes(&aes_iv)?;
            writer.write_bytes(&der)?;
            writer.write_u8(0)?;
            Ok(())
        },
        |writer| make_p2p_init_packet(writer, session),
    )
}

pub(super) fn make_hello_server(session: &SessionCore) -> Result<Vec<u8>> {
    // From HelloServer in libIOTCAPIs.so.
    const EXPECTED_CONTENT_SIZE: usize = 0x8;

    let sequence_number = 0x0;
    let random_nonce = 0xbcda;

    let mut packet = vec![0; 0x18];
    let mut packet_cursor = Cursor::new(packet.as_mut_slice());
    write_packet(
        &mut packet_cursor,
        PacketHeader {
            command: CmdType::HelloServer as u16,
            channel_id: 0,
            flags: PacketFlags::from_bits_retain(0x2),
            command_options: 0x3f,
            session_id: 0,
            channel_flags: 0,
            content_size: EXPECTED_CONTENT_SIZE as u16,
        },
        |writer| {
            writer.write_le_u32(sequence_number)?; // TODO: feels like some sequence number that is incremented each time. And randomized at start.
            writer.write_le_u16(random_nonce)?;
            writer.write_le_u16(0)?;
            Ok(())
        },
        EXPECTED_CONTENT_SIZE,
    )?;

    charlie_cypher::cypher(&mut packet);

    Ok(packet)
}

pub(super) fn make_record_send_p2p_keep_alive(record_sid: u32) -> Result<Vec<u8>> {
    // From iotcRecordSendP2PKeepAlive in libIOTCAPIs.so: a completely
    // unencrypted type 5 record, 0x18 bytes total.
    const RECORD_SIZE: usize = 0xc;

    let mut record = vec![0u8; constants::RECORD_HEADER_SIZE + RECORD_SIZE];
    let mut writer = Cursor::new(record.as_mut_slice());
    writer.write_le_u32(constants::RECORD_MAGIC_NUMBER)?;
    writer.write_u8(1)?;
    writer.write_u8(RecordType::KeepAlive as u8)?;
    writer.write_le_u16(RECORD_SIZE as u16)?;
    writer.write_le_u32(0xffff)?;
    writer.write_le_u32(record_sid)?;
    writer.write_le_u32(0)?;
    // The original also writes *(undefined4 *)(param_4 + 4) here, which we
    // could not identify; zero for now.
    writer.write_le_u32(0)?;

    Ok(record)
}


// From the case 0x01 handler in iotcRecordHandler in libIOTCAPIs.so.
fn parse_record_handshake(buffer: &[u8], session: &SessionCore) -> Result<Vec<ServerEntry>> {
    let (header, payload) = read_record_header_and_decrypt(
        buffer,
        RecordDecryption::Aes128Gcm {
            key: session.aes_key,
            iv: session.aes_iv,
        },
    )?;
    assert!(header.session_id == session.session_id);

    let servers = match parse_packet(&payload, PacketCypher::Plaintext)? {
        PacketOutcome::ServerList {
            nonce1,
            uid,
            servers,
        } => {
            assert!(nonce1 == session.nonce1);
            assert!(uid == session.device_id);
            servers
        }
        outcome => bail!("Unexpected packet in the master handshake response: {:?}", outcome),
    };

    Ok(servers)
}

// From the case '\x03' handler in iotcRecordHandler in libIOTCAPIs.so: the
// response to the P2PInitHandshakeReq, AES-GCM encrypted with the peer
// keys. Pure parse: validates against the session (nonce2, device uid)
// and returns the facts for the state machines to apply.
fn parse_record_p2p_init_handshake_resp(
    buffer: &[u8],
    session: &SessionCore,
    from: SocketAddr,
) -> Result<(u32, u16)> {
    let peer = session
        .peers
        .get(&from)
        .with_context(|| format!("Handshake response from an unknown peer: {}", from))?;

    let (_, packet) = read_record_header_and_decrypt(
        buffer,
        RecordDecryption::Aes128Gcm {
            key: peer.aes_key,
            iv: peer.aes_iv,
        },
    )?;

    if packet.len() != 0x48 {
        warn!(
            "Unexpected handshake response packet size: 0x{:x}",
            packet.len()
        );
        crate::utils::hexdump(&packet);
    }

    let (record_sid, keepalive_interval) = match parse_packet(&packet, PacketCypher::Plaintext)? {
        PacketOutcome::P2PHandshake {
            nonce2,
            uid,
            record_sid,
            keepalive_interval,
        } => {
            if nonce2 != session.nonce2 {
                bail!("Wrong nonce2 in handshake response: 0x{:04x}", nonce2);
            }
            if uid != session.device_id {
                bail!("Wrong device id in handshake response: {:?}", uid);
            }
            (record_sid, keepalive_interval)
        }
        outcome => bail!("Unexpected packet in the handshake response: {:?}", outcome),
    };

    debug!(
        "Handshake response accepted: record sid 0x{:08x}, keepalive interval {}s",
        record_sid, keepalive_interval
    );

    Ok((record_sid, keepalive_interval))
}

// From the case '\x05' handler in iotcRecordHandler in libIOTCAPIs.so: the
// server's keepalive, fully unencrypted. Pure parse: returns the echoed
// record SID.
fn parse_record_keep_alive(buffer: &[u8]) -> Result<u32> {
    let (_, body) = read_record_header_and_decrypt(buffer, RecordDecryption::Unencrypted)?;
    let record_sid = Cursor::new(&body).read_le_u32()?;

    debug!("Keepalive received (record sid 0x{:08x})", record_sid);

    Ok(record_sid)
}

pub fn parse(
    buffer: &[u8],
    session: Option<&SessionCore>,
    from: Option<SocketAddr>,
) -> Result<ParseOutcome> {
    // From iotcRecordHandler in libIOTCAPIs.so / handle_buffer
    let mut buf = Cursor::new(buffer);
    let record_magic_number = buf.read_le_u32()?;

    if record_magic_number != constants::RECORD_MAGIC_NUMBER {
        // Process as packet. From FUN_0004a770 in libIOTCAPIs.so: a
        // standalone packet is only processed when the datagram is exactly
        // the header plus the announced content size; anything else is
        // silently dropped.
        let outcome = match parse_packet(buffer, PacketCypher::Charlie) {
            Ok(outcome) => outcome,
            Err(err)
                if matches!(
                    err.downcast_ref::<ParseError>(),
                    Some(ParseError::InvalidPacketContentSize)
                ) =>
            {
                return Ok(ParseOutcome::Packet)
            }
            Err(err) => return Err(err),
        };
        return match outcome {
            PacketOutcome::HelloClient { address } => Ok(ParseOutcome::HelloClient { address }),
            PacketOutcome::DeviceStatus { online, uid } => {
                Ok(ParseOutcome::DeviceStatus { online, uid })
            }
            _ => Ok(ParseOutcome::Packet),
        };
    }

    // Process as record
    let Some(session) = session else {
        warn!("Received a record without a session to attach it to");
        return Ok(ParseOutcome::Other);
    };

    // Peek at the record type to dispatch; each record parser frames and
    // decrypts its record with read_record_header_and_decrypt.
    let mut cursor = Cursor::new(buffer);
    let _ = cursor.read_le_u32()?; // magic number already read
    let _ = cursor.read_u8()?; // version
    let record_type: RecordType = cursor.read_u8()?.try_into()?;

    match record_type {
        RecordType::MasterHandshake => {
            let servers = parse_record_handshake(buffer, session)?;
            Ok(ParseOutcome::ServerList(servers))
        }
        RecordType::P2PInitHandshakeResp => {
            let Some(from) = from else {
                bail!("Received a handshake response without a source address");
            };
            let (record_sid, keepalive_interval) =
                parse_record_p2p_init_handshake_resp(buffer, session, from)?;
            Ok(ParseOutcome::HandshakeResp {
                record_sid,
                keepalive_interval,
            })
        }
        RecordType::KeepAlive => {
            let record_sid = parse_record_keep_alive(buffer)?;
            Ok(ParseOutcome::KeepAlive { record_sid })
        }
        RecordType::KeyPush => {
            // TODO: Reverse the type 4 record (cmd 0x30d) further: per-peer
            // decryption with the raw record SID as AAD, the random id
            // replay check and the 8x16-byte key entries.
            warn!("Received a key push record ({} bytes)", buffer.len());
            crate::utils::hexdump(buffer);
            Ok(ParseOutcome::Other)
        }
        RecordType::P2PInitHandshakeReq => {
            warn!("Received an unexpected P2PInitHandshakeReq record");
            Ok(ParseOutcome::Other)
        }
    }
}


// The following structs mirror Session.field_0x740 in libIOTCAPIs.so: the main connection state
// machine, as a typestate.

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use crate::iotc::session::test_public_key;

    #[test]
    fn master_handshake_uses_the_common_record_layout() {
        let session = SessionCore::new(0x12345678, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");

        let record = make_record_send_master_handshake(&session).unwrap();

        assert_eq!(record.len(), constants::RECORD_HEADER_SIZE + 0x100);
        assert_eq!(&record[0..4], &constants::RECORD_MAGIC_NUMBER.to_le_bytes());
        assert_eq!(record[4], 1);
        assert_eq!(record[5], RecordType::MasterHandshake as u8);
        assert_eq!(&record[6..8], &0x100_u16.to_le_bytes());
        assert_eq!(&record[8..12], &session.session_id.to_le_bytes());
    }

    #[test]
    fn keep_alive_record_round_trips_through_parse() {
        let session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");

        let record = make_record_send_p2p_keep_alive(0xdeadbeef).unwrap();
        let outcome = parse(&record, Some(&session), None).unwrap();

        assert!(matches!(
            outcome,
            ParseOutcome::KeepAlive {
                record_sid: 0xdeadbeef
            }
        ));
    }

    #[test]
    fn p2p_init_handshake_resp_round_trips_through_parse() {
        let mut session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");
        let peer_addr = SocketAddr::from((Ipv4Addr::new(5, 6, 7, 8), 3478));
        let pub_key = test_public_key().unwrap();
        let peer = session.get_or_create_peer(&peer_addr, &pub_key).unwrap();
        let (aes_key, aes_iv) = (peer.aes_key, peer.aes_iv);

        // The server's type 3 response: an AES-GCM record (peer keys)
        // carrying a packet (cmd 0x218) that echoes nonce2, carries the
        // record sid and the device uid, with the keepalive interval at
        // content offset 0x34.
        const CONTENT_SIZE: usize = 0x38;
        const PACKET_SIZE: usize = constants::PACKET_HEADER_SIZE + CONTENT_SIZE;
        const RECORD_SIZE: usize = PACKET_SIZE + constants::RECORD_AES_TAG_SIZE;

        let record = write_record(
            RecordType::P2PInitHandshakeResp,
            session.session_id,
            RECORD_SIZE,
            PACKET_SIZE,
            RecordEncryption::Aes128Gcm { key: aes_key, iv: aes_iv },
            |_| Ok(()),
            |writer| {
                write_packet(
                    writer,
                    PacketHeader {
                        command: CmdType::P2PHandshake as u16,
                        channel_id: 0,
                        flags: PacketFlags::empty(),
                        command_options: 0,
                        session_id: 0,
                        channel_flags: 0,
                        content_size: CONTENT_SIZE as u16,
                    },
                    |writer| {
                        writer.write_le_u16(session.nonce2)?;
                        writer.write_le_u16(0)?;
                        writer.write_le_u32(0xdeadbeef)?;
                        writer.write_bytes(&session.device_id)?;
                        // Pad up to the keepalive interval at content offset 0x34.
                        writer.write_bytes(&[0; 0x34 - 0x1c])?;
                        writer.write_le_u16(42)?;
                        writer.write_le_u16(0)?;
                        Ok(())
                    },
                    CONTENT_SIZE,
                )
            },
        )
        .unwrap();

        let outcome = parse(&record, Some(&session), Some(peer_addr)).unwrap();

        assert!(matches!(
            outcome,
            ParseOutcome::HandshakeResp {
                record_sid: 0xdeadbeef,
                keepalive_interval: 42
            }
        ));
    }

    #[test]
    fn master_handshake_resp_round_trips_through_parse() {
        let session = SessionCore::new(0x12345678, "ABCDEFGHIJKLMNOPQRST", *b"TESTKEY1");

        // The master's type 1 response: an AES-GCM record (session keys)
        // carrying a packet (cmd 0x100c) that echoes nonce1 and the device
        // uid, then a type 9 entry with one server candidate at content
        // offset 0x3a.
        let server_ip = Ipv4Addr::new(5, 6, 7, 8);
        let server_port = 3478u16;
        let der = test_public_key().unwrap().public_key_to_der().unwrap();

        const CONTENT_SIZE: usize = 0x3a + 2 + 4 + 0x6c;
        const PACKET_SIZE: usize = constants::PACKET_HEADER_SIZE + CONTENT_SIZE;
        const RECORD_SIZE: usize = PACKET_SIZE + constants::RECORD_AES_TAG_SIZE;

        let record = write_record(
            RecordType::MasterHandshake,
            session.session_id,
            RECORD_SIZE,
            PACKET_SIZE,
            RecordEncryption::Aes128Gcm {
                key: session.aes_key,
                iv: session.aes_iv,
            },
            |_| Ok(()),
            |writer| {
                write_packet(
                    writer,
                    PacketHeader {
                        command: CmdType::P2PInitHandshakeResp as u16,
                        channel_id: 0,
                        flags: PacketFlags::empty(),
                        command_options: 0,
                        session_id: 0,
                        channel_flags: 0,
                        content_size: CONTENT_SIZE as u16,
                    },
                    |writer| {
                        writer.write_le_u16(session.nonce1)?;
                        writer.write_le_u16(0)?;
                        writer.write_bytes(&session.device_id)?;
                        // Pad up to the entry table at content offset 0x3a.
                        writer.write_bytes(&[0; 0x3a - 0x18])?;
                        writer.write_le_u16(1)?; // One entry.
                        // The type 9 entry: the server list.
                        writer.write_le_u16(9)?;
                        writer.write_le_u16(0x6c)?;
                        writer.write_le_u16(0)?;
                        writer.write_be_u16(server_port)?;
                        writer.write_be_u32(u32::from(server_ip))?;
                        writer.write_le_u64(0)?;
                        let mut der_key = [0; 0x5c];
                        der_key[..der.len()].copy_from_slice(&der);
                        writer.write_bytes(&der_key)?;
                        Ok(())
                    },
                    CONTENT_SIZE,
                )?;
                // The master server sends its response packet with version
                // 0x1d, not PACKET_VERSION.
                writer.get_mut()[2] = 0x1d;
                Ok(())
            },
        )
        .unwrap();

        let outcome = parse(&record, Some(&session), None).unwrap();

        let ParseOutcome::ServerList(servers) = outcome else {
            panic!("Expected a server list");
        };
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].ip_address, IpAddr::V4(server_ip));
        assert_eq!(servers[0].port, server_port);
    }

}
