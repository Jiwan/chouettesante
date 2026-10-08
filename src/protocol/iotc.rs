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
use tokio::time::timeout;
use tracing::{debug, warn};
use tracing_subscriber::field::debug;

use crate::utils::BinaryWriter;
use crate::{charlie_cypher, charlie_cypher::decypher, utils::BinaryReader};

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
    session_id: u16, // Speculative field.
    channel_flags: u8, // Speculative field.
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

fn make_record_send_master_handshake(session: &IotcSession) -> Result<Vec<u8>> {
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
    assert_eq!(ciphertext.len() + tag.len(), record_size - extended_header_size);

    record_writer.write_bytes(&ciphertext)?;
    record_writer.write_bytes(&tag)?;
    let final_size = record_writer.position() as usize;
    assert_eq!(final_size, expected_total_size);

    record.truncate(final_size);

    Ok(record)
}

fn make_p2p_init_packet(packet_writer: &mut Cursor<&mut [u8]>, session: &IotcSession) -> Result<()> {
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
    session: &mut IotcSession,
    server_entry: &ServerEntry,
) -> Result<Vec<u8>> {
    // From iotcRecordSendP2PInitHandshakeReq in libIOTCAPIs.so.
    const RECORD_SIZE: usize = 0xac;
    const EXPECTED_PACKET_SIZE: usize = 0x34;

    let peer_address = SocketAddr::from((server_entry.ip_address, server_entry.port));
    let P2PPeer { aes_key, aes_iv, .. } =
        *session.get_or_create_peer(&peer_address, &server_entry.pub_key)?;

    let der = session.ecdh_key.public_key_to_der()?;
    assert_eq!(der.len(), 0x5b, "ECDH DER key must be exactly 0x5B bytes");

    make_record(
        RecordType::P2PInitHandshakeReq,
        session.session_id,
        RECORD_SIZE,
        EXPECTED_PACKET_SIZE,
        RecordEncryption::Aes128Gcm { key: aes_key, iv: aes_iv },
        move |writer| {
            writer.write_bytes(&aes_iv)?;
            writer.write_bytes(&der)?;
            writer.write_u8(0)?;
            Ok(())
        },
        |writer| make_p2p_init_packet(writer, session),
    )
}

fn make_hello_server(session: &IotcSession) -> Result<Vec<u8>> {
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

fn make_record_send_p2p_keep_alive(peer: &P2PPeer) -> Result<Vec<u8>> {
    // From iotcRecordSendP2PKeepAlive in libIOTCAPIs.so: a completely
    // unencrypted type 5 record, 0x18 bytes total.
    const RECORD_SIZE: usize = 0xc;

    let record_sid = peer
        .record_sid
        .context("Cannot send a keepalive before the peer record SID is known")?;

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
// response to the P2PInitHandshakeReq.
fn parse_record_p2p_init_handshake_resp(
    buffer: &[u8],
    record_size: usize,
    session: &mut IotcSession,
    from: SocketAddr,
) -> Result<u16> {
    // Layout: header (aad) | payload | tag
    // Size:     0x0c         |   ...   | 0x10
    let aad = &buffer[0..constants::RECORD_HEADER_SIZE];
    let ciphertext = &buffer[constants::RECORD_HEADER_SIZE
        ..constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE];
    let tag =
        &buffer[constants::RECORD_HEADER_SIZE + record_size - constants::RECORD_AES_TAG_SIZE..];

    let (nonce2, device_id) = (session.nonce2, session.device_id);
    let peer = session
        .peer_mut(&from)
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
    let content_size = reader.read_le_u16()? as usize;
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
    if nonce2_echo != nonce2 {
        return Err(anyhow::anyhow!(
            "Wrong nonce2 in handshake response: 0x{:04x}",
            nonce2_echo
        ));
    }

    let _ = content.read_le_u16()?;
    let record_sid = content.read_le_u32()?;
    let uid = content.read_bytes::<20>()?;
    if uid != device_id {
        return Err(anyhow::anyhow!(
            "Wrong device id in handshake response: {:?}",
            uid
        ));
    }

    // Keepalive interval, in seconds, at content offset 0x34.
    let keepalive_interval =
        Cursor::new(&packet[PACKET_HEADER_SIZE + 0x34..]).read_le_u16()?;

    peer.record_sid = Some(record_sid);
    session.state = SessionState::Connected;

    debug!(
        "Handshake response accepted: record sid 0x{:08x}, keepalive interval {}s (content size 0x{:x})",
        record_sid, keepalive_interval, content_size
    );

    Ok(keepalive_interval)
}

// From the case '\x05' handler in iotcRecordHandler in libIOTCAPIs.so: the
// server's keepalive, fully unencrypted.
fn parse_record_keep_alive(
    buffer: &[u8],
    record_size: usize,
    session: &IotcSession,
    from: SocketAddr,
) -> Result<()> {
    let mut reader = Cursor::new(buffer);
    reader.set_position(constants::RECORD_HEADER_SIZE as u64);
    let record_sid = reader.read_le_u32()?;

    let peer = session
        .peers
        .get(&from)
        .with_context(|| format!("Keepalive from an unknown peer: {}", from))?;

    if Some(record_sid) != peer.record_sid {
        return Err(anyhow::anyhow!(
            "Keepalive from the wrong peer sid: 0x{:08x} vs {:?}",
            record_sid,
            peer.record_sid
        ));
    }

    debug!("Keepalive received (record size 0x{:x})", record_size);

    Ok(())
}

pub struct IotcSession {
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
    state: SessionState,
}

struct P2PPeer {
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    // Learned from the type 3 handshake response (content offset 0x04) and
    // echoed in every type 4/5 record from this peer. See FUN_0004d570.
    record_sid: Option<u32>,
}

// Mirrors Session.field_0x740 in libIOTCAPIs.so.
#[derive(Debug, PartialEq)]
enum SessionState {
    Connecting,
    // Set when the type 3 P2PInitHandshakeResp is accepted (state 6 in the
    // binary).
    Connected,
}

#[derive(Debug)]
pub struct ServerEntry {
    ip_address: IpAddr,
    port: u16,
    pub_key: PKey<Public>,
}

impl IotcSession {
    fn new(session_id: u32, uid: &str) -> Result<Self> {
        let device_id: String = uid.to_lowercase();
        let nonce1 = rand::random::<u16>();
        let nonce2 = rand::random::<u16>();

        let mut aes_key: [u8; 16] = [0; 16];
        rand::fill(&mut aes_key);

        let mut aes_iv: [u8; 12] = [0; 12];
        rand::fill(&mut aes_iv);

        Ok(Self {
            session_id,
            device_id: device_id.as_bytes().try_into()?,
            aes_key,
            aes_iv,
            nonce1,
            nonce2,
            ecdh_key: generate_ecdh_key()?,
            peers: HashMap::new(),
            state: SessionState::Connecting,
        })
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
                P2PPeer { aes_key, aes_iv, record_sid: None },
            );
        }

        Ok(self.peers.get(address).unwrap())
    }

    fn peer_mut(&mut self, address: &SocketAddr) -> Option<&mut P2PPeer> {
        self.peers.get_mut(address)
    }
}

pub struct IotcSessionManager {
    sessions: HashMap<u32, IotcSession>,
    session_id_counter: u32,
}

impl IotcSessionManager {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_id_counter: 0,
        }
    }

    fn create_session(&mut self, uid: &str) -> &mut IotcSession {
        self.session_id_counter += 1;
        self.sessions
            .entry(self.session_id_counter)
            .or_insert_with(|| IotcSession::new(self.session_id_counter, uid).unwrap())
    }

    fn get_session(&self, session_id: u32) -> Option<&IotcSession> {
        self.sessions.get(&session_id)
    }

    fn get_session_mut(&mut self, session_id: u32) -> Option<&mut IotcSession> {
        self.sessions.get_mut(&session_id)
    }
}

pub fn parse_packet(buffer: &mut [u8]) -> Result<()> {
    let buffer_len = buffer.len();
    let (header, content) = buffer
        .split_at_mut_checked(PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    decypher(header);

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
            packet_size,
            PACKET_HEADER_SIZE,
            buffer_len
        );
        return Ok(());
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

    decypher(&mut content[..cyphered_size]);

    // From: _IOTC_Packet_Handler in libIOTCAPIs.so
    let cmd_type_enum = CmdType::try_from(cmd_type);

    if cmd_type_enum.is_err() {
        warn!("Unknown cmd type: 0x{:04x}", cmd_type);
        return Ok(());
    }

    let mut reader: Cursor<&[u8]> = Cursor::new(content);

    match cmd_type_enum.unwrap() {
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
        CmdType::DeviceOfflineStatus => {
            // From _IOTC_Packet_Handler: the content is the 20-byte device
            // uid; the server reports the device as not connected there.
            if content.len() >= 20 {
                let uid = &content[..20];
                debug!("Device {:?} reported offline by this server", uid);
            }
        }
        CmdType::DeviceOnlineStatus => {
            debug!("Device online status packet received");
        }
        CmdType::HelloServer => {
            debug!("Received HelloServer packet");
        }
        CmdType::HelloClient => {
            // addNatRecord in libIOTCAPIs.so
            {
                let _ = reader.read_le_u16()?; // Probably the af type?
                let our_port = reader.read_be_u16()?;
                let our_address: u32 = reader.read_be_u32()?;
                let our_address = IpAddr::V4(Ipv4Addr::from_bits(our_address));
                let _ = reader.read_le_u64()?; // unknown

                debug!("Client IP address: {}:{}", our_address, our_port);
            }
        }
    }

    Ok(())
}

fn parse_record_handshake<T>(
    buffer: &[u8],
    cursor: &mut Cursor<T>,
    session: &IotcSession,
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
    HandshakeResp { keepalive_interval: u16 },
    KeepAlive,
    Packet,
    Other,
}

pub fn parse(
    buffer: &mut [u8],
    session: Option<&mut IotcSession>,
    from: Option<SocketAddr>,
) -> Result<ParseOutcome> {
    // From iotcRecordHandler in libIOTCAPIs.so / handle_buffer
    let mut buf = Cursor::new(&*buffer);
    let record_magic_number = buf.read_le_u32()?;

    if record_magic_number != constants::RECORD_MAGIC_NUMBER {
        // Process as packet
        parse_packet(buffer)?;
        return Ok(ParseOutcome::Packet);
    }

    // Process as record
    assert!(buffer.len() >= constants::RECORD_HEADER_SIZE);
    assert!(buffer.len() <= constants::RECORD_PACKET_MAX_SIZE);

    let mut cursor = Cursor::new(&*buffer);
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
            let servers = parse_record_handshake(&buffer, &mut cursor, session)?;
            Ok(ParseOutcome::ServerList(servers))
        }
        RecordType::P2PInitHandshakeResp => {
            let Some(from) = from else {
                bail!("Received a handshake response without a source address");
            };
            let keepalive_interval =
                parse_record_p2p_init_handshake_resp(&buffer, record_size, session, from)?;
            Ok(ParseOutcome::HandshakeResp {
                keepalive_interval,
            })
        }
        RecordType::KeepAlive => {
            let Some(from) = from else {
                bail!("Received a keepalive without a source address");
            };
            parse_record_keep_alive(&buffer, record_size, session, from)?;
            Ok(ParseOutcome::KeepAlive)
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
    // From IOTC_Connect_UDP_Inner, AddUDPPreCheckTask and FUN_00037d90 in
    // libIOTCAPIs.so.

    let mut session_manager = IotcSessionManager::new();
    let session = session_manager.create_session(uid);

    let master_domain_name = get_master_domain_name(region);

    debug!("Master domain name: {}", master_domain_name);

    // From AddUDPQueryDeviceInfoTask: the handshake goes to every resolved
    // master address, resent every 500ms (FUN_00036e90) until a response.
    let master_addrs: Vec<SocketAddr> = lookup_host((master_domain_name.as_str(), 10240))
        .await
        .context("Failed to resolve the master domain")?
        .collect();

    if master_addrs.is_empty() {
        bail!("Failed to resolve master domain {}", master_domain_name);
    }

    debug!("Master addresses: {:?}", master_addrs);

    let record = make_record_send_master_handshake(session)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let master_deadline = Instant::now() + Duration::from_secs(60);
    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];

    let (n, recv_addr) = 'master: loop {
        if Instant::now() > master_deadline {
            bail!("Timed out waiting for the master handshake response");
        }

        for addr in &master_addrs {
            socket.send_to(&record, addr).await?;
        }

        match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => break 'master (n, from),
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {}
        }
    };

    debug!("Master handshake sent, response received from {}", recv_addr);

    buf.truncate(n);

    let server_entries = match parse(&mut buf, Some(&mut *session), Some(recv_addr))? {
        ParseOutcome::ServerList(servers) => servers,
        outcome => bail!("Expected the master handshake response, got {:?}", outcome),
    };

    debug!(
        "Master returned {} P2P server candidates",
        server_entries.len()
    );

    // From HelloServer in libIOTCAPIs.so: one hello packet to every
    // candidate, so that the P2P servers learn our public address.
    let hello_packet = make_hello_server(session)?;

    for server_entry in &server_entries {
        let target = SocketAddr::from((server_entry.ip_address, server_entry.port));
        socket.send_to(&hello_packet, target).await?;
    }

    // From AddUDPPreCheckTask: the P2P init handshake request goes to every
    // candidate, and is resent every 500ms until a response or a 60s
    // timeout (FUN_00037d90).
    let handshake_records: Vec<(SocketAddr, Vec<u8>)> = server_entries
        .iter()
        .map(|server_entry| {
            let addr = SocketAddr::from((server_entry.ip_address, server_entry.port));
            Ok((
                addr,
                make_record_send_p2p_init_handshake_req(session, server_entry)?,
            ))
        })
        .collect::<Result<_>>()?;

    let connect_deadline = Instant::now() + Duration::from_secs(60);
    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];

    let (keepalive_interval, connected_addr) = 'connect: loop {
        if Instant::now() > connect_deadline {
            bail!("Timed out waiting for the P2P handshake response");
        }

        for (addr, record) in &handshake_records {
            socket.send_to(record, addr).await?;
        }

        loop {
            match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    buf.truncate(n);
                    debug!("Received {} bytes from {}", n, from);

                    match parse(&mut buf, Some(&mut *session), Some(from))? {
                        ParseOutcome::HandshakeResp {
                            keepalive_interval,
                        } => break 'connect (keepalive_interval, from),
                        _ => continue,
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_elapsed) => break, // 500ms without a response: resend.
            }
        }
    };

    debug!("Connected to P2P server {}", connected_addr);

    // From iotcRecordSendP2PKeepAlive: unencrypted type 5 records at the
    // server-provided interval (in seconds, from the handshake response).
    let keepalive_period = Duration::from_secs(keepalive_interval.max(1) as u64);
    let mut last_keepalive = Instant::now();
    let observe_until = Instant::now() + Duration::from_secs(30);

    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];

    loop {
        if last_keepalive.elapsed() >= keepalive_period {
            let peer = session.peers.get(&connected_addr).unwrap();
            let record = make_record_send_p2p_keep_alive(peer)?;
            socket.send_to(&record, connected_addr).await?;
            last_keepalive = Instant::now();
            debug!("Keepalive sent");
        }

        match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                buf.truncate(n);
                debug!("Received {} bytes from {}", n, from);
                parse(&mut buf, Some(&mut *session), Some(from))?;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {}
        }

        if Instant::now() > observe_until {
            break;
        }
    }

    Ok(())
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
        let mut session = IotcSession::new(1, "ABCDEFGHIJKLMNOPQRST").unwrap();

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
    fn master_handshake_uses_the_common_record_layout() {
        let session = IotcSession::new(0x12345678, "ABCDEFGHIJKLMNOPQRST").unwrap();

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
