use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use openssl::{
    ec::EcKey,
    pkey::{PKey, Public},
};
use rand::prelude::*;

use anyhow::{bail, Context, Result};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de, Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use tokio::net::{lookup_host, UdpSocket};
use tracing::{debug, warn};
use tracing_subscriber::field::debug;

use crate::{
    charlie_cypher,
    charlie_cypher::decypher,
    utils::{BinaryReader, BinaryWriter, SocketUtils},
};

use super::{
    constants,
    crypto::{
        decrypt_aes_128_gcm, derive_aes_128_key, encrypt_aes_128_gcm, generate_ecdh_key,
        rsa_encrypt, rsa_encrypted_size,
    },
};

const PACKET_HEADER_SIZE: usize = 0x10;

#[derive(Error, Debug)]
enum ParseError {
    #[error("InvalidHeaderSize")]
    InvalidHeaderSize,
    #[error("WrongPacketMagicNumber")]
    WrongPacketMagicNumber,
    #[error("WrongVersion")]
    WrongVersion,
    #[error("InvalidCypheredContentSize")]
    InvalidCypheredContentSize,
    #[error("WrongFlagType")]
    WrongFlagType,
    #[error("InvalidSessionId")]
    InvalidSessionId,
    #[error("InvalidChannelId")]
    InvalidChannelId,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct PacketFlags: u8 {
        const CypherExtendHeaderOnly = 0b0001;
        const UnknownFlag0x2 = 0b0010;
        const UnknownFlag0x4 = 0b0100;
        const UnknownFlag0x8 = 0b1000;
    }
}

#[repr(u8)]
enum RecordType {
    MasterHandshake = 0x1,
    P2PInitHandshakeReq = 0x2,
    // From the switch in iotcRecordHandler in libIOTCAPIs.so: only types
    // 1, 3, 4 and 5 are parsed on the client side. Type 2 records are
    // send-only.
    P2PInitHandshakeResp = 0x3,
    KeyPush = 0x4,
    KeepAlive = 0x5,
}

enum RecordEncryption {
    Rsa,
    Aes128Gcm { key: [u8; 16], iv: [u8; 12] },
}

impl RecordEncryption {
    fn encrypted_size(&self, plaintext_size: usize) -> usize {
        match self {
            Self::Rsa => rsa_encrypted_size(plaintext_size),
            Self::Aes128Gcm { .. } => plaintext_size + constants::RECORD_AES_TAG_SIZE,
        }
    }

    fn encrypt(self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Self::Rsa => {
                let expected_size = rsa_encrypted_size(plaintext.len());
                let mut ciphertext = vec![0; expected_size];
                let encrypted_size = rsa_encrypt(plaintext, &mut ciphertext);
                assert_eq!(encrypted_size, expected_size);
                Ok((ciphertext, Vec::new()))
            }
            Self::Aes128Gcm { key, iv } => encrypt_aes_128_gcm(plaintext, aad, key, iv),
        }
    }
}

#[derive(Error, Debug)]
enum RecordConversionError {
    #[error("InvalidRecordType")]
    InvalidRecordType,
}

impl TryFrom<u8> for RecordType {
    type Error = RecordConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1 => Ok(RecordType::MasterHandshake),
            0x2 => Ok(RecordType::P2PInitHandshakeReq),
            0x3 => Ok(RecordType::P2PInitHandshakeResp),
            0x4 => Ok(RecordType::KeyPush),
            0x5 => Ok(RecordType::KeepAlive),
            _ => Err(RecordConversionError::InvalidRecordType),
        }
    }
}

fn make_record<WriteExtendedHeader, WritePayload>(
    record_type: RecordType,
    session_id: u32,
    expected_record_size: usize,
    expected_payload_size: usize,
    encryption: RecordEncryption,
    write_extended_header: WriteExtendedHeader,
    write_payload: WritePayload,
) -> Result<Vec<u8>>
where
    WriteExtendedHeader: FnOnce(&mut Cursor<&mut [u8]>) -> Result<()>,
    WritePayload: FnOnce(&mut Cursor<&mut [u8]>) -> Result<()>,
{
    assert!(expected_payload_size <= constants::RECORD_PACKET_MAX_SIZE);

    let mut record = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let mut record_writer = Cursor::new(record.as_mut_slice());
    record_writer.write_le_u32(constants::RECORD_MAGIC_NUMBER)?;
    record_writer.write_u8(1)?;
    record_writer.write_u8(record_type as u8)?;
    let record_header_size_position = record_writer.position();
    record_writer.write_le_u16(0)?;
    record_writer.write_le_u32(session_id)?;
    assert_eq!(
        record_writer.position() as usize,
        constants::RECORD_HEADER_SIZE
    );

    write_extended_header(&mut record_writer)?;
    let header_size = record_writer.position() as usize;
    assert!(header_size >= constants::RECORD_HEADER_SIZE);
    assert!(header_size <= constants::RECORD_PACKET_MAX_SIZE);

    let mut payload = vec![0; constants::RECORD_PACKET_MAX_SIZE - header_size];
    let mut payload_writer = Cursor::new(payload.as_mut_slice());

    write_payload(&mut payload_writer)?;
    let payload_size = payload_writer.position() as usize;
    payload.truncate(payload_size);

    assert_eq!(payload_size, expected_payload_size);

    let extended_header_size = header_size - constants::RECORD_HEADER_SIZE;
    let record_size = extended_header_size + encryption.encrypted_size(payload_size);
    assert_eq!(record_size, expected_record_size);
    let expected_total_size = constants::RECORD_HEADER_SIZE + expected_record_size;
    assert!(expected_total_size <= constants::RECORD_PACKET_MAX_SIZE);

    let wire_record_size: u16 = record_size
        .try_into()
        .context("Record size does not fit in its wire field")?;

    // The record size is part of the AES-GCM AAD and must be finalized before
    // encrypting the payload.
    {
        let current_position = record_writer.position();
        record_writer.set_position(record_header_size_position);
        record_writer.write_le_u16(wire_record_size)?;
        record_writer.set_position(current_position);
    }

    let aad = &record_writer.get_ref()[..header_size];
    let (ciphertext, tag) = encryption.encrypt(&payload, aad)?;
    assert_eq!(
        ciphertext.len() + tag.len(),
        record_size - extended_header_size
    );

    record_writer.write_bytes(&ciphertext)?;
    record_writer.write_bytes(&tag)?;
    let final_size = record_writer.position() as usize;
    assert_eq!(final_size, expected_total_size);

    record.truncate(final_size);

    Ok(record)
}

#[repr(u16)]
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
enum CmdType {
    P2PInit = 0x217,
    // Response to the P2PInitHandshakeReq, carried by a type 3 record.
    // Also the cmd used by the keepalive exchange.
    P2PHandshake = 0x218,
    // Key push from the P2P server, carried by a type 4 record.
    KeyPush = 0x30d,
    // Device status notifications from the P2P servers, from
    // _IOTC_Packet_Handler in libIOTCAPIs.so.
    DeviceOfflineStatus = 0x227,
    DeviceOnlineStatus = 0x229,
    UnknownCmd0x408 = 0x408,
    P2PInitHandshakeReq = 0x100b,
    P2PInitHandshakeResp = 0x100c,
    HelloServer = 0x8003,
    HelloClient = 0x8004,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MasterRegion {
    CN,
    EU,
    US,
    ASIA,
}

fn get_realm() -> &'static str {
    // Technically, the realm is more complicated than this and must be extracted from the nebulaDomainFromLicense you get in SetLicenseKey.
    // But that involves decrypting the licensee key and that feels unnecessary for now.
    // It seems that all suffixes end-up mapping to the same domain name.
    return "tutk.iotcplatform.com";
}

fn get_master_domain_name(region: MasterRegion) -> String {
    // See GetMasterDomainName in libTUTKGlobalAPIs.so
    let master_type = "c-master";

    return format!(
        "{}-{}-{}",
        serde_json::to_string(&region)
            .unwrap()
            .trim_matches('"')
            .to_lowercase(),
        master_type,
        get_realm()
    );
}

struct PacketHeader {
    command: u16,
    channel_id: u8,
    flags: u8,
    command_options: u16, // Speculative field.
    session_id: u16,      // Speculative field.
    channel_flags: u8,    // Speculative field.
}

// Writes a packet, from _IOTC_Packet_Handler in libIOTCAPIs.so. The header is
// 0x10 bytes, little-endian unless noted otherwise:
//
// Offset  Size  Field
// 0x00    2     Magic number (PACKET_MAGIC_NUMBER, 0x0204)
// 0x02    1     Version (PACKET_VERSION, 0x1e)
// 0x03    1     Flags (PacketFlags)
// 0x04    2     Content size
// 0x06    2     Unknown
// 0x08    2     Command (CmdType)
// 0x0a    2     Command options
// 0x0c    2     Session id
// 0x0e    1     Channel id
// 0x0f    1     Channel flags
// 0x10    ...   write_content data (will match content size)
fn write_packet<WriteContent>(
    packet_writer: &mut Cursor<&mut [u8]>,
    header: PacketHeader,
    write_content: WriteContent,
    expected_content_size: usize,
) -> Result<()>
where
    WriteContent: FnOnce(&mut Cursor<&mut [u8]>) -> Result<()>,
{
    let packet_start = packet_writer.position();
    packet_writer.write_le_u16(constants::PACKET_MAGIC_NUMBER)?;
    packet_writer.write_u8(constants::PACKET_VERSION)?;
    packet_writer.write_u8(header.flags)?;

    let content_size_position = packet_writer.position();
    packet_writer.write_le_u16(0)?;
    packet_writer.write_le_u16(0)?;
    packet_writer.write_le_u16(header.command)?;
    packet_writer.write_le_u16(header.command_options)?;
    packet_writer.write_le_u16(header.session_id)?;
    packet_writer.write_u8(header.channel_id)?;
    packet_writer.write_u8(header.channel_flags)?;

    let content_start = packet_writer.position();
    write_content(packet_writer)?;
    let packet_end = packet_writer.position();
    let content_size = (packet_end - content_start) as usize;
    assert_eq!(content_size, expected_content_size);

    let content_size: u16 = content_size
        .try_into()
        .context("Packet content size does not fit in its wire field")?;

    packet_writer.set_position(content_size_position);
    packet_writer.write_le_u16(content_size)?;
    packet_writer.set_position(packet_end);

    Ok(())
}

fn make_record_send_master_handshake(session: &SessionCore) -> Result<Vec<u8>> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    const RECORD_SIZE: usize = 0x100;
    const EXPECTED_PACKET_SIZE: usize = 0x58;
    const EXPECTED_CONTENT_SIZE: usize = 0x48;

    make_record(
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
                    flags: 0,
                    command_options: 0x18,
                    session_id: 0,
                    channel_flags: 0,
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
            flags: 0,
            command_options: 0x24,
            session_id: 0,
            channel_flags: 0,
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
            writer.write_le_u64(0)?; // *(undefined8 *)*(byte **)(p2p_config + 4)
            Ok(())
        },
        EXPECTED_CONTENT_SIZE,
    )
}

fn make_record_send_p2p_init_handshake_req(
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

    make_record(
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

fn make_hello_server(session: &SessionCore) -> Result<Vec<u8>> {
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
            flags: 0x2,
            command_options: 0x3f,
            session_id: 0,
            channel_flags: 0,
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

fn make_record_send_p2p_keep_alive(record_sid: u32) -> Result<Vec<u8>> {
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

// From the case '\x03' handler in iotcRecordHandler in libIOTCAPIs.so: the
// response to the P2PInitHandshakeReq. Pure parse: validates against the
// session (nonce2, device uid) and the peer credentials, and returns the
// facts for the state machines to apply.
fn parse_record_p2p_init_handshake_resp(
    buffer: &[u8],
    record_size: usize,
    session: &SessionCore,
    from: SocketAddr,
) -> Result<(u32, u16)> {
    // Layout: header (aad) | payload | tag
    // Size:     0x0c         |   ...   | 0x10
    let aad = &buffer[0..constants::RECORD_HEADER_SIZE];
    let ciphertext = &buffer[constants::RECORD_HEADER_SIZE
        ..constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE];
    let tag =
        &buffer[constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE..];

    let peer = session
        .peers
        .get(&from)
        .with_context(|| format!("Handshake response from an unknown peer: {}", from))?;

    let packet = decrypt_aes_128_gcm(ciphertext, aad, tag, peer.aes_key, peer.aes_iv)?;

    if packet.len() != 0x48 {
        warn!(
            "Unexpected handshake response packet size: 0x{:x}",
            packet.len()
        );
        crate::utils::hexdump(&packet);
    }

    let mut reader = Cursor::new(&packet);
    let magic_number = reader.read_le_u16()?;
    if magic_number != constants::PACKET_MAGIC_NUMBER {
        return Err(ParseError::WrongPacketMagicNumber.into());
    }
    let _ = reader.read_u8()?; // Version.
    let _ = reader.read_u8()?; // Flags.
    let _content_size = reader.read_le_u16()? as usize;
    let _ = reader.read_le_u16()?; // Unknown.

    let cmd_type = reader.read_le_u16()?;
    if cmd_type != CmdType::P2PHandshake as u16 {
        return Err(anyhow::anyhow!(
            "Unexpected handshake response cmd: 0x{:04x}",
            cmd_type
        ));
    }

    let mut content = Cursor::new(&packet[PACKET_HEADER_SIZE..]);
    let nonce2_echo = content.read_le_u16()?;
    if nonce2_echo != session.nonce2 {
        return Err(anyhow::anyhow!(
            "Wrong nonce2 in handshake response: 0x{:04x}",
            nonce2_echo
        ));
    }

    let _ = content.read_le_u16()?;
    let record_sid = content.read_le_u32()?;
    let uid = content.read_bytes::<20>()?;
    if uid != session.device_id {
        return Err(anyhow::anyhow!(
            "Wrong device id in handshake response: {:?}",
            uid
        ));
    }

    // Keepalive interval, in seconds, at content offset 0x34.
    let keepalive_interval = Cursor::new(&packet[PACKET_HEADER_SIZE + 0x34..]).read_le_u16()?;

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
    let mut reader = Cursor::new(buffer);
    reader.set_position(constants::RECORD_HEADER_SIZE as u64);
    let record_sid = reader.read_le_u32()?;

    debug!("Keepalive received (record sid 0x{:08x})", record_sid);

    Ok(record_sid)
}

// Mirrors the per-server state in the Session server table (state byte at
// +0x7e7) in libIOTCAPIs.so: one machine per server peer, tracking how the
// rendezvous with the device progresses through that particular server.
#[derive(Debug, PartialEq)]
enum PeerState {
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

struct P2PPeer {
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    state: PeerState,
}

// Shared session data, owned by all states. Sort off mirror Session in libIOTCAPIs.so.
pub struct SessionCore {
    session_id: u32,
    device_id: [u8; 20],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    nonce1: u16,
    nonce2: u16,
    ecdh_key: EcKey<openssl::pkey::Private>,
    // Mirrors Session.peers[0..0xb] in libIOTCAPIs.so: one set of P2P
    // credentials per server address.
    peers: HashMap<SocketAddr, P2PPeer>,
    // Our public address as seen by the P2P servers, from addNatRecord.
    public_address: Option<SocketAddr>,
}

// The following structs mirror Session.field_0x740 in libIOTCAPIs.so: the main connection state
// machine, as a typestate.

// No connection started yet.
struct Idle {
    core: SessionCore,
}

// Master handshake records resent to every master address on each tick
// until one answers (state 1).
struct MasterHandshake {
    core: SessionCore,
    addrs: Vec<SocketAddr>,
    deadline: Instant,
}

// P2P init handshake requests resent to every candidate on each tick
// (states 4-5). The binary's states 2-4 (hello/pre-session wait) are folded
// into the MasterHandshake -> P2PHandshaking transition since we do not
// implement the pre-session wait.
struct P2PHandshaking {
    core: SessionCore,
    servers: Vec<ServerEntry>,
    deadline: Instant,
    offline_warning_sent: bool,
}

// One peer carries the session; unencrypted keepalives at the
// server-provided interval (state 6).
struct Connected {
    core: SessionCore,
    peer: SocketAddr,
    record_sid: u32,
    keepalive_period: Duration,
    next_keepalive: Instant,
    // Observe the connected session for 30s for now; becomes "forever"
    // once the data channels are implemented.
    observe_until: Instant,
}

enum Session {
    Idle(Idle),
    MasterHandshake(MasterHandshake),
    P2PHandshaking(P2PHandshaking),
    Connected(Connected),
}

// The main machine's outputs: one datagram to put on the wire per action,
// or the end of the connection observation. The records are crafted last
// minute by the machine itself.
#[derive(Debug)]
enum ConnectionAction {
    Send { data: Vec<u8>, to: SocketAddr },
    Finished,
}

impl ConnectionAction {
    fn data(&self) -> &[u8] {
        match self {
            ConnectionAction::Send { data, .. } => data,
            ConnectionAction::Finished => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerEntry {
    ip_address: IpAddr,
    port: u16,
    pub_key: PKey<Public>,
}

impl SessionCore {
    fn new(session_id: u32, uid: &str) -> Self {
        let device_id: String = uid.to_lowercase();
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
            peers: HashMap::new(),
            public_address: None,
        }
    }

    // Mirrors iotcGetP2PKeyInfo/iotcUpdateP2PAESKeys in libIOTCAPIs.so: the
    // peer AES key is derived from the ECDH shared secret with that peer's
    // public key and the IV is freshly randomized per peer, both cached by
    // server address.
    fn get_or_create_peer(
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
}

impl Session {
    // Only an idle session can start connecting; any other state is a
    // driver bug, mirroring iotc_connect failing on an in-use session.
    fn start_connection(self, master_addrs: Vec<SocketAddr>) -> Result<Session> {
        match self {
            Session::Idle(idle) => Ok(Session::MasterHandshake(
                idle.start_connection(master_addrs),
            )),
            _ => bail!("Only an idle session can start connecting"),
        }
    }

    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        match self {
            Session::Idle(_) => Ok(vec![]),
            Session::MasterHandshake(state) => state.on_tick(),
            Session::P2PHandshaking(state) => state.on_tick(),
            Session::Connected(state) => state.on_tick(),
        }
    }

    // Consumes the session and returns the next one alongside the actions:
    // transitions are moves between states, not writes into a borrowed
    // self.
    fn on_datagram(
        self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        match self {
            Session::Idle(state) => state.on_datagram(data, from),
            Session::MasterHandshake(state) => state.on_datagram(data, from),
            Session::P2PHandshaking(state) => state.on_datagram(data, from),
            Session::Connected(state) => state.on_datagram(data, from),
        }
    }
}

impl Idle {
    // Starts the connection machine: the master handshake will be crafted
    // and resent to every address on each tick until one answers.
    fn start_connection(self, master_addrs: Vec<SocketAddr>) -> MasterHandshake {
        MasterHandshake {
            core: self.core,
            addrs: master_addrs,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    // Datagrams still update the peers and the public address, but an
    // idle session never transitions.
    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        Ok((Session::Idle(self), vec![]))
    }
}

impl MasterHandshake {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.deadline {
            bail!("Timed out waiting for the master handshake response");
        }

        let data = make_record_send_master_handshake(&self.core)?;

        Ok(self
            .addrs
            .iter()
            .map(|to| ConnectionAction::Send {
                data: data.clone(),
                to: *to,
            })
            .collect())
    }

    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        match outcome {
            ParseOutcome::ServerList(servers) => {
                let (state, actions) = self.enter_p2p_handshaking(servers)?;
                Ok((Session::P2PHandshaking(state), actions))
            }
            _ => Ok((Session::MasterHandshake(self), vec![])),
        }
    }

    // MasterHandshake -> P2PHandshaking: the entry actions send a hello and
    // a handshake request to every candidate. Crafting the handshake
    // records also creates the peers, each starting in
    // AwaitingHandshakeResp.
    fn enter_p2p_handshaking(
        self,
        servers: Vec<ServerEntry>,
    ) -> Result<(P2PHandshaking, Vec<ConnectionAction>)> {
        debug!("Master returned {} P2P server candidates", servers.len());

        let addrs: Vec<SocketAddr> = servers
            .iter()
            .map(|server| SocketAddr::from((server.ip_address, server.port)))
            .collect();

        // Entry actions: one hello packet per candidate (the same packet,
        // so it is crafted once and cloned), then one handshake record per
        // candidate, which also creates the peers.
        let mut core = self.core;
        let hello_packet = make_hello_server(&core)?;
        let mut actions: Vec<ConnectionAction> = addrs
            .iter()
            .map(|to| ConnectionAction::Send {
                data: hello_packet.clone(),
                to: *to,
            })
            .collect();

        for (server, to) in servers.iter().zip(addrs) {
            actions.push(ConnectionAction::Send {
                data: make_record_send_p2p_init_handshake_req(&mut core, server)?,
                to,
            });
        }

        Ok((
            P2PHandshaking {
                core,
                servers,
                deadline: Instant::now() + Duration::from_secs(60),
                offline_warning_sent: false,
            },
            actions,
        ))
    }
}

impl P2PHandshaking {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.deadline {
            bail!("Timed out waiting for the P2P handshake response");
        }

        // One record per candidate; this also creates the peers on the
        // first pass (their credentials are cached afterwards). The
        // servers and the crafting core are disjoint fields, so both may
        // be borrowed at once.
        self.servers
            .iter()
            .map(|server| {
                Ok(ConnectionAction::Send {
                    data: make_record_send_p2p_init_handshake_req(&mut self.core, server)?,
                    to: SocketAddr::from((server.ip_address, server.port)),
                })
            })
            .collect()
    }

    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        match outcome {
            // A master response that arrives once the handshakes are
            // already running is a duplicate: no way back.
            ParseOutcome::ServerList(_) => {
                debug!("Ignoring a duplicate master handshake response");
                Ok((Session::P2PHandshaking(self), vec![]))
            }
            ParseOutcome::HandshakeResp {
                record_sid,
                keepalive_interval,
            } => Ok((
                self.enter_connected(from, record_sid, keepalive_interval),
                vec![],
            )),
            ParseOutcome::DeviceStatus { .. } => {
                // One aggregated warning once every peer reports the device
                // as offline there.
                if self.core.device_offline_everywhere() && !self.offline_warning_sent {
                    self.offline_warning_sent = true;
                    warn!(
                        "The device is reported offline by all {} P2P servers",
                        self.core.peers.len()
                    );
                }

                Ok((Session::P2PHandshaking(self), vec![]))
            }
            _ => Ok((Session::P2PHandshaking(self), vec![])),
        }
    }

    // P2PHandshaking -> Connected: this peer carries the session from now
    // on; keepalives start at the server-provided interval. The per-peer
    // machine must have promoted this peer already (by apply_peer_outcome
    // above); otherwise the session stays handshaking.
    fn enter_connected(
        self,
        peer: SocketAddr,
        record_sid: u32,
        keepalive_interval: u16,
    ) -> Session {
        if !matches!(
            self.core.peers.get(&peer).map(|p| &p.state),
            Some(PeerState::Connected { .. })
        ) {
            return Session::P2PHandshaking(self);
        }

        debug!("Connected to P2P server {}", peer);

        let keepalive_period = Duration::from_secs(keepalive_interval.max(1) as u64);
        let now = Instant::now();

        Session::Connected(Connected {
            core: self.core,
            peer,
            record_sid,
            keepalive_period,
            next_keepalive: now + keepalive_period,
            observe_until: now + Duration::from_secs(30),
        })
    }
}

impl Connected {
    fn on_tick(&mut self) -> Result<Vec<ConnectionAction>> {
        let now = Instant::now();

        if now > self.observe_until {
            return Ok(vec![ConnectionAction::Finished]);
        }

        if now >= self.next_keepalive {
            self.next_keepalive = now + self.keepalive_period;

            return Ok(vec![ConnectionAction::Send {
                data: make_record_send_p2p_keep_alive(self.record_sid)?,
                to: self.peer,
            }]);
        }

        Ok(vec![])
    }

    // Once connected, datagrams only feed the per-peer machines (keepalive
    // last-alive bookkeeping and so on); the session never transitions
    // back.
    fn on_datagram(
        mut self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(Session, Vec<ConnectionAction>)> {
        let outcome = parse(data, Some(&self.core), Some(from))?;
        self.core.apply_peer_outcome(&outcome, from);

        Ok((Session::Connected(self), vec![]))
    }
}

impl SessionCore {
    // Applies a parsed wire fact to the per-peer state machines. The main
    // machine transitions are handled by the states' on_datagram.
    fn apply_peer_outcome(&mut self, outcome: &ParseOutcome, from: SocketAddr) {
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
    fn device_offline_everywhere(&self) -> bool {
        !self.peers.is_empty()
            && self
                .peers
                .values()
                .all(|p| matches!(p.state, PeerState::DeviceReportedOffline))
    }
}

pub struct IotcSessionManager {
    sessions: HashMap<u32, Session>,
    session_id_counter: u32,
}

impl IotcSessionManager {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_id_counter: 0,
        }
    }

    fn create_session(&mut self, uid: &str) -> Session {
        self.session_id_counter += 1;
        let session_id = self.session_id_counter;
        Session::Idle(Idle {
            core: SessionCore::new(session_id, uid),
        })
    }

    fn take_session(&mut self, session_id: u32) -> Option<Session> {
        self.sessions.remove(&session_id)
    }
}

// The parsed facts of a standalone packet (not wrapped in a record), from
// _IOTC_Packet_Handler in libIOTCAPIs.so. Parsing stays pure: the state
// machines apply these facts.
#[derive(Debug, PartialEq)]
enum PacketOutcome {
    HelloClient { address: SocketAddr },
    DeviceStatus { online: bool, uid: [u8; 20] },
    Ignored,
}

pub fn parse_packet(buffer: &[u8]) -> Result<PacketOutcome> {
    let buffer_len = buffer.len();
    let (header, content) = buffer
        .split_at_checked(PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    let mut header = header.to_vec();
    decypher(&mut header);

    let mut reader = Cursor::new(header);
    let magic_number = reader.read_le_u16()?;

    if magic_number != constants::PACKET_MAGIC_NUMBER {
        return Err(ParseError::WrongPacketMagicNumber.into());
    }

    let version = reader.read_u8()?;

    if version != constants::PACKET_VERSION {
        return Err(ParseError::WrongVersion.into());
    }

    let packet_flags = PacketFlags::from_bits_retain(reader.read_u8()?);
    let packet_size = reader.read_le_u16()?;
    let _unknown0x6 = reader.read_le_u16()?; // unknown

    let cmd_type = reader.read_le_u16()?;
    let _command_options = reader.read_le_u16()?; // TODO: Confirm this field's meaning.
    let _session_id = reader.read_le_u16()?; // TODO: Confirm this field's meaning.
    let channelId = reader.read_u8()?;
    let _channel_flags = reader.read_u8()?; // TODO: Confirm this field's meaning.

    // From FUN_0004a770 in libIOTCAPIs.so: a packet is only processed when
    // the datagram is exactly the header plus the announced content size;
    // anything else is silently dropped.
    if packet_size as usize + PACKET_HEADER_SIZE != buffer_len {
        warn!(
            "Dropping packet with inconsistent size: {} + 0x{:x} != {}",
            packet_size, PACKET_HEADER_SIZE, buffer_len
        );
        return Ok(PacketOutcome::Ignored);
    }

    // When the CypherExtendHeaderOnly flag is set, only the first 0x30
    // content bytes are cyphered — but if the content is shorter than that,
    // the whole content is cyphered (charlie_crypt clamps cryptedSize to
    // the buffer size).
    let cyphered_size = if packet_flags.contains(PacketFlags::CypherExtendHeaderOnly) {
        0x30.min(content.len())
    } else {
        content.len()
    };

    let mut content = content.to_vec();
    decypher(&mut content[..cyphered_size]);

    // From: _IOTC_Packet_Handler in libIOTCAPIs.so
    let cmd_type_enum = match CmdType::try_from(cmd_type) {
        Ok(cmd) => cmd,
        Err(_) => {
            warn!("Unknown cmd type: 0x{:04x}", cmd_type);
            return Ok(PacketOutcome::Ignored);
        }
    };

    let mut reader: Cursor<&[u8]> = Cursor::new(content.as_slice());

    match cmd_type_enum {
        CmdType::UnknownCmd0x408 => {
            if packet_flags.contains(PacketFlags::UnknownFlag0x4) {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if content.len() < 0x0c {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if !packet_flags.contains(PacketFlags::UnknownFlag0x8) {
                // TODO
            } else {
                let extended_header_size = reader.read_le_u32()? as usize;
                let session1 = reader.read_le_u32()?; // unknown
                let session2 = reader.read_le_u32()?; // unknown

                if session1 == 0 {
                    return Err(ParseError::InvalidSessionId.into());
                }

                // Search for session1 and session2 in gSessionInfo to extract the right session.

                if channelId >= 0x20 {
                    return Err(ParseError::InvalidChannelId.into());
                }

                let content = &content[extended_header_size..];

                let mut reader = Cursor::new(content);
                let _ = reader.read_u8()?; // unknown
                let _ = reader.read_u8()?; // unknown
                let _ = reader.read_le_u16()?; // unknown

                // content == DTLS 1.2 packet
                // As a stream: https://docs.rs/ringbuf/latest/ringbuf/
                // Supplied to a SslStream: https://docs.rs/openssl/0.10.71/openssl/ssl/index.html
            }
        }
        CmdType::P2PInit | CmdType::P2PInitHandshakeReq | CmdType::P2PInitHandshakeResp => {
            debug!("Received P2P handshake packet");
        }
        CmdType::P2PHandshake | CmdType::KeyPush => {
            debug!("Received P2P session packet");
        }
        CmdType::DeviceOfflineStatus | CmdType::DeviceOnlineStatus => {
            // From _IOTC_Packet_Handler: the content starts with the
            // 20-byte device uid; 0x227 reports the device as not
            // connected to this server, 0x229 as connected.
            if content.len() >= 20 {
                let online = cmd_type == CmdType::DeviceOnlineStatus as u16;
                let uid: [u8; 20] = content[..20].try_into().unwrap();
                return Ok(PacketOutcome::DeviceStatus { online, uid });
            }
        }
        CmdType::HelloServer => {
            debug!("Received HelloServer packet");
        }
        CmdType::HelloClient => {
            // From addNatRecord in libIOTCAPIs.so: a sockaddr_in followed
            // by 8 unknown bytes, carrying our public address as seen by
            // the server.
            if content.len() >= 16 {
                let _ = reader.read_le_u16()?; // Probably the af type?
                let port = reader.read_be_u16()?;
                let address: u32 = reader.read_be_u32()?;
                let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(address)), port);
                let _ = reader.read_le_u64()?; // unknown

                return Ok(PacketOutcome::HelloClient { address });
            }
        }
    }

    Ok(PacketOutcome::Ignored)
}

fn parse_record_handshake<T>(
    buffer: &[u8],
    cursor: &mut Cursor<T>,
    session: &SessionCore,
) -> Result<Vec<ServerEntry>>
where
    T: AsRef<[u8]>,
{
    let record_size = cursor.read_le_u16()? as usize;
    let session_id = cursor.read_le_u32()?;

    assert!(session_id == session.session_id);

    // Layout: header (aad) | payload | tag
    // Size:     0x0c       |   ...   | 0x10
    let add = &buffer[0..constants::RECORD_HEADER_SIZE];
    let ciphertext = &buffer[constants::RECORD_HEADER_SIZE
        ..constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE];
    let tag =
        &buffer[constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE..];
    let result = decrypt_aes_128_gcm(ciphertext, add, tag, session.aes_key, session.aes_iv)?;

    println!("Decrypted payload:");
    crate::utils::hexdump(&result);

    let mut payload_cursor = Cursor::new(&result);
    let handshake_magic_number = payload_cursor.read_le_u16()?;
    assert!(handshake_magic_number == constants::PACKET_MAGIC_NUMBER);
    let _ = payload_cursor.read_u8()?;
    let _ = payload_cursor.read_u8()?;
    let len = payload_cursor.read_le_u32()?;
    assert!(((len + 0x1c) as usize) < constants::RECORD_PACKET_MAX_SIZE);
    let unknown = payload_cursor.read_le_u16()?;
    assert!(unknown == 0x100c);
    payload_cursor.seek_relative(6)?;
    let nonce = payload_cursor.read_le_u16()?;
    assert!(nonce == session.nonce1);
    let _ = payload_cursor.read_le_u16()?;
    let uid = payload_cursor.read_bytes::<20>()?;
    assert!(uid == session.device_id);

    payload_cursor.seek(std::io::SeekFrom::Start(0x4a))?;
    let entry_count = payload_cursor.read_le_u16()?;
    assert!(entry_count != 0);

    let mut servers = vec![];

    for _ in 0..entry_count {
        let entry_type = payload_cursor.read_le_u16()?;
        let entry_size = payload_cursor.read_le_u16()? as u64;
        let entry_offset = payload_cursor.position();

        match entry_type {
            9 => {
                /* server entries or something */
                let server_count = entry_size / 0x6C;

                for _ in 0..server_count {
                    let _ = payload_cursor.read_le_u16()?;
                    let port = payload_cursor.read_be_u16()?;
                    let ip_address: u32 = payload_cursor.read_be_u32()?;
                    let _ = payload_cursor.read_le_u64()?;

                    let mut der_key = [0; 0x5c];
                    payload_cursor.read_exact(&mut der_key)?;
                    let pub_key = PKey::public_key_from_der(&der_key)?;

                    servers.push(ServerEntry {
                        ip_address: IpAddr::V4(Ipv4Addr::from_bits(ip_address)),
                        port,
                        pub_key,
                    });

                    debug!("Server: {:?}", servers.last());
                }
            }
            1 => {
                let _unknown1 = payload_cursor.read_le_u16()?;
                let _unknown2 = payload_cursor.read_le_u16()?;
                let _unknown3 = payload_cursor.read_le_u16()?;
                // It looks like those 3 short are reversed: unknown3, unknown2, unknown1.
            }
            _ => {
                warn!("Unknown entry type: {}", entry_type);
            }
        }

        payload_cursor.set_position(entry_offset + entry_size);
    }

    Ok(servers)
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

pub fn parse(
    buffer: &[u8],
    session: Option<&SessionCore>,
    from: Option<SocketAddr>,
) -> Result<ParseOutcome> {
    // From iotcRecordHandler in libIOTCAPIs.so / handle_buffer
    let mut buf = Cursor::new(buffer);
    let record_magic_number = buf.read_le_u32()?;

    if record_magic_number != constants::RECORD_MAGIC_NUMBER {
        // Process as packet
        return match parse_packet(buffer)? {
            PacketOutcome::HelloClient { address } => Ok(ParseOutcome::HelloClient { address }),
            PacketOutcome::DeviceStatus { online, uid } => {
                Ok(ParseOutcome::DeviceStatus { online, uid })
            }
            PacketOutcome::Ignored => Ok(ParseOutcome::Packet),
        };
    }

    // Process as record
    assert!(buffer.len() >= constants::RECORD_HEADER_SIZE);
    assert!(buffer.len() <= constants::RECORD_PACKET_MAX_SIZE);

    let mut cursor = Cursor::new(buffer);
    let _ = cursor.read_le_u32()?; // magic number already read
    let _ = cursor.read_u8()?; // version
    let record_type: RecordType = cursor.read_u8()?.try_into()?;
    let record_size = u16::from_le_bytes([buffer[6], buffer[7]]) as usize;

    let Some(session) = session else {
        warn!("Received a record without a session to attach it to");
        return Ok(ParseOutcome::Other);
    };

    match record_type {
        RecordType::MasterHandshake => {
            let servers = parse_record_handshake(buffer, &mut cursor, session)?;
            Ok(ParseOutcome::ServerList(servers))
        }
        RecordType::P2PInitHandshakeResp => {
            let Some(from) = from else {
                bail!("Received a handshake response without a source address");
            };
            let (record_sid, keepalive_interval) =
                parse_record_p2p_init_handshake_resp(buffer, record_size, session, from)?;
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

pub async fn connect(region: MasterRegion, uid: &str) -> Result<()> {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so.

    let mut session_manager = IotcSessionManager::new();
    let mut session = session_manager.create_session(uid);

    let master_domain_name = get_master_domain_name(region);

    debug!("Master domain name: {}", master_domain_name);

    // From AddUDPQueryDeviceInfoTask: the handshake goes to every resolved
    // master address.
    let master_addrs: Vec<SocketAddr> = lookup_host((master_domain_name.as_str(), 10240))
        .await
        .context("Failed to resolve the master domain")?
        .collect();

    if master_addrs.is_empty() {
        bail!("Failed to resolve master domain {}", master_domain_name);
    }

    debug!("Master addresses: {:?}", master_addrs);

    let mut session = session.start_connection(master_addrs)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut reception_buffer = vec![0; constants::RECORD_PACKET_MAX_SIZE];

    // Entry action of the MasterHandshake state: contact the masters right
    // away instead of waiting for the first tick.
    let mut actions = session.on_tick()?;

    loop {
        for action in actions {
            match action {
                ConnectionAction::Send { data, to } => {
                    socket.send_to(&data, to).await?;
                }
                ConnectionAction::Finished => {
                    debug!("Connection finished, exiting loop");
                    return Ok(());
                }
            }
        }

        actions = match socket
            .rcv_from_timeout(&mut reception_buffer, Duration::from_millis(500))
            .await
        {
            Ok(Ok((data, from))) => {
                debug!("Received {} bytes from {}", data.len(), from);
                let (next, actions) = session.on_datagram(data, from)?;
                session = next;
                actions
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => session.on_tick()?,
        };
    }
}

#[cfg(test)]
mod packet_writer_tests {
    use super::*;

    fn test_public_key() -> Result<PKey<Public>> {
        let key = generate_ecdh_key()?;
        let der = key.public_key_to_der()?;
        Ok(PKey::public_key_from_der(&der)?)
    }

    #[test]
    fn p2p_peer_credentials_are_cached_per_server_address() {
        let mut session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST").unwrap();

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
        let mut session = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST").unwrap();
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
                flags: 0,
                command_options: 0,
                session_id: 0,
                channel_flags: 0,
            },
            |writer| {
                writer.write_bytes(&session.device_id)?;
                Ok(())
            },
            20,
        )
        .unwrap();
        charlie_cypher::cypher(&mut packet);

        let outcome = parse_packet(&packet).unwrap();
        assert_eq!(
            outcome,
            PacketOutcome::DeviceStatus {
                online: false,
                uid: session.device_id
            }
        );

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

    #[test]
    fn connection_state_machine_transitions_through_the_phases() {
        let core = SessionCore::new(1, "ABCDEFGHIJKLMNOPQRST").unwrap();
        let session = Session::Idle(Idle { core });
        assert!(matches!(session, Session::Idle(_)));

        let master_addr = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 10240));
        let mut session = session.start_connection(vec![master_addr]).unwrap();
        assert!(matches!(session, Session::MasterHandshake(_)));

        // On a tick, the machine crafts the master record last minute and
        // sends it to every master address.
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, .. }] if to == &master_addr
        ));
        assert_eq!(
            actions[0].data().len(),
            constants::RECORD_HEADER_SIZE + 0x100
        );

        // The master returned a server list: entry actions of the
        // P2PHandshaking state (hello + handshake to every candidate, peers
        // created).
        let entry = ServerEntry {
            ip_address: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            port: 3478,
            pub_key: test_public_key().unwrap(),
        };
        let peer_addr = SocketAddr::from((Ipv4Addr::new(5, 6, 7, 8), 3478));
        let Session::MasterHandshake(state) = session else {
            panic!("The session must be in the master handshake state");
        };
        let (state, actions) = state.enter_p2p_handshaking(vec![entry]).unwrap();
        let mut session = Session::P2PHandshaking(state);
        // One hello per candidate, then one handshake record per candidate.
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            actions[0],
            ConnectionAction::Send { ref to, .. } if to == &peer_addr
        ));
        assert!(matches!(
            actions[1],
            ConnectionAction::Send { ref to, .. } if to == &peer_addr
        ));
        assert_eq!(actions[0].data().len(), 0x18);
        assert_eq!(
            actions[1].data().len(),
            constants::RECORD_HEADER_SIZE + 0xac
        );
        let Session::P2PHandshaking(state) = &session else {
            panic!("The session must be handshaking");
        };
        assert_eq!(state.core.peers.len(), 1);
        assert_eq!(
            state.core.peers[&peer_addr].state,
            PeerState::AwaitingHandshakeResp
        );

        // Each tick recrafts one handshake record per candidate.
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, .. }] if to == &peer_addr
        ));

        // A duplicate master response cannot even be expressed anymore:
        // only the MasterHandshake state knows how to enter P2P handshaking.

        // The handshake response is accepted: the per-peer machine promotes
        // the peer, then the main machine enters Connected with this peer
        // carrying the session and keepalives at the server-provided
        // interval.
        let Session::P2PHandshaking(mut state) = session else {
            panic!("The session must be handshaking");
        };
        state.core.apply_peer_outcome(
            &ParseOutcome::HandshakeResp {
                record_sid: 0xdeadbeef,
                keepalive_interval: 42,
            },
            peer_addr,
        );
        assert!(matches!(
            state.core.peers[&peer_addr].state,
            PeerState::Connected {
                record_sid: 0xdeadbeef,
                keepalive_interval: 42,
                ..
            }
        ));
        let mut session = state.enter_connected(peer_addr, 0xdeadbeef, 42);
        assert!(matches!(
            &session,
            Session::Connected(Connected {
                peer,
                record_sid,
                keepalive_period,
                ..
            }) if *peer == peer_addr && *record_sid == 0xdeadbeef && *keepalive_period == Duration::from_secs(42)
        ));

        // Keepalives are not due yet...
        assert!(session.on_tick().unwrap().is_empty());

        // ...then they are.
        if let Session::Connected(Connected { next_keepalive, .. }) = &mut session {
            *next_keepalive -= Duration::from_secs(60);
        }
        let actions = session.on_tick().unwrap();
        assert!(matches!(
            actions.as_slice(),
            [ConnectionAction::Send { ref to, ref data }] if to == &peer_addr && data.len() == 0x18
        ));
    }

    #[test]
    fn master_handshake_uses_the_common_record_layout() {
        let session = SessionCore::new(0x12345678, "ABCDEFGHIJKLMNOPQRST").unwrap();

        let record = make_record_send_master_handshake(&session).unwrap();

        assert_eq!(record.len(), constants::RECORD_HEADER_SIZE + 0x100);
        assert_eq!(&record[0..4], &constants::RECORD_MAGIC_NUMBER.to_le_bytes());
        assert_eq!(record[4], 1);
        assert_eq!(record[5], RecordType::MasterHandshake as u8);
        assert_eq!(&record[6..8], &0x100_u16.to_le_bytes());
        assert_eq!(&record[8..12], &session.session_id.to_le_bytes());
    }

    #[test]
    fn write_packet_writes_header_and_patches_content_size() {
        const PACKET_START: usize = 3;

        let mut buffer = [0; 32];
        let mut writer = Cursor::new(buffer.as_mut_slice());
        writer.set_position(PACKET_START as u64);

        write_packet(
            &mut writer,
            PacketHeader {
                command: 0x1234,
                channel_id: 0x56,
                flags: 0x78,
                command_options: 0xdef0,
                session_id: 0x9abc,
                channel_flags: 0x12,
            },
            |writer| {
                writer.write_bytes(&[0xaa, 0xbb, 0xcc])?;
                Ok(())
            },
            3,
        )
        .unwrap();

        assert_eq!(
            writer.position() as usize,
            PACKET_START + constants::PACKET_HEADER_SIZE + 3
        );
        assert_eq!(
            &buffer[PACKET_START..PACKET_START + 2],
            &constants::PACKET_MAGIC_NUMBER.to_le_bytes()
        );
        assert_eq!(buffer[PACKET_START + 2], constants::PACKET_VERSION);
        assert_eq!(buffer[PACKET_START + 3], 0x78);
        assert_eq!(&buffer[PACKET_START + 4..PACKET_START + 6], &[3, 0]);
        assert_eq!(&buffer[PACKET_START + 6..PACKET_START + 8], &[0, 0]);
        assert_eq!(&buffer[PACKET_START + 8..PACKET_START + 10], &[0x34, 0x12]);
        assert_eq!(
            &buffer[PACKET_START + 10..PACKET_START + 14],
            &[0xf0, 0xde, 0xbc, 0x9a]
        );
        assert_eq!(buffer[PACKET_START + 14], 0x56);
        assert_eq!(buffer[PACKET_START + 15], 0x12);
        assert_eq!(
            &buffer[PACKET_START + constants::PACKET_HEADER_SIZE
                ..PACKET_START + constants::PACKET_HEADER_SIZE + 3],
            &[0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    #[should_panic]
    fn write_packet_rejects_an_unexpected_content_size() {
        let mut buffer = [0; 32];
        let mut writer = Cursor::new(buffer.as_mut_slice());

        write_packet(
            &mut writer,
            PacketHeader {
                command: 0,
                channel_id: 0,
                flags: 0,
                command_options: 0,
                session_id: 0,
                channel_flags: 0,
            },
            |writer| {
                writer.write_u8(0)?;
                Ok(())
            },
            2,
        )
        .unwrap();
    }
}
