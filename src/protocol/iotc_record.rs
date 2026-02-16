use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Public},
    rsa::{self, Rsa},
    symm::{Cipher, Crypter, Mode},
    dh::DhRef
};
use rand::prelude::*;

use anyhow::{Context, Result};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de, Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use tokio::{net::{UdpSocket, lookup_host}};
use tracing::{debug, warn};
use tracing_subscriber::field::debug;

use crate::utils::BinaryWriter;
use crate::{charlie_cypher, charlie_cypher::decypher, utils::BinaryReader};

use super::constants;

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
        const UnknownFlag0x2 = 0b0100;
        const UnknownFlag0x4 = 0b0100;
        const UnknownFlag0x8 = 0b1000;
    }
}

#[repr(u8)]
enum RecordType {
    MasterHandshake = 0x1,
    P2PInitHandshakeReq = 0x2,
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
            _ => Err(RecordConversionError::InvalidRecordType),
        }
    }
}

#[repr(u16)]
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
enum CmdType {
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

fn rsa_encrypt(from: &[u8], to: &mut [u8]) -> usize {
    // From TUTK3rdRSAEncrypt in libTUTKGlobalAPIs.so.
    let rsa_key = Rsa::public_key_from_pem(constants::PUB_RSA_KEY.as_bytes()).unwrap();

    let modulus: usize = rsa_key.size() as usize;
    let padded_size = from.len().next_multiple_of(modulus);

    // Note that this padding strategy is horrifying.
    // It should be something like PKCS padding, but it is what the original code does.
    let mut padded_from = Vec::with_capacity(padded_size);
    padded_from.extend_from_slice(from);
    padded_from.resize(padded_size, 0);

    for (chunk_from, chunk_to) in padded_from.chunks(modulus).zip(to.chunks_mut(modulus)) {
        rsa_key
            .public_encrypt(chunk_from, chunk_to, rsa::Padding::NONE)
            .unwrap();
    }

    padded_size
}

fn make_record_send_master_handshake(session: &IotcSession) -> std::io::Result<Vec<u8>> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    let rsa_encrypted_size = 0;

    let mut packet = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.write_le_u32(constants::RECORD_MAGIC_NUMBER)?;
    packet_cursor.write_u8(1)?;
    packet_cursor.write_u8(RecordType::MasterHandshake as u8)?;
    let rsa_encrypted_size_offset = packet_cursor.position();
    packet_cursor.write_le_u16(rsa_encrypted_size)?;
    packet_cursor.write_le_u32(session.session_id)?;

    assert!(packet_cursor.position() as usize == constants::RECORD_HEADER_SIZE);

    let mut payload = vec![0; 0x58];
    let mut payload_cursor = Cursor::new(&mut payload);
    payload_cursor.write_le_u16(constants::PACKET_MAGIC_NUMBER)?;
    payload_cursor.write_u8(constants::PACKET_VERSION)?;
    payload_cursor.write_u8(0x0)?;
    payload_cursor.write_le_u32(0x48)?;
    payload_cursor.write_le_u16(0x100b)?;
    payload_cursor.write_le_u16(0x18)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_le_u16(session.nonce1)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_bytes(&session.aes_key)?;
    payload_cursor.write_bytes(&session.aes_iv)?;
    payload_cursor.write_bytes(&session.device_id)?;
    payload_cursor.write_bytes(&get_realm().as_bytes()[0..0x10])?;
    payload_cursor.write_u8(0x6)?;
    payload_cursor.write_u8((session.session_id == 0xffff) as u8)?;

    let encrypted_size = rsa_encrypt(&payload, &mut packet[constants::RECORD_HEADER_SIZE..]);
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.set_position(rsa_encrypted_size_offset);
    packet_cursor.write_le_u16(encrypted_size as u16)?;

    packet.truncate(constants::RECORD_HEADER_SIZE + encrypted_size);

    Ok(packet)
}


fn derive_aes_128_key(private_key: &EcKey<openssl::pkey::Private>, public_key: &PKey<Public>) -> Result<[u8; 16]> {
    // create AES key from ECDH shared secret (ECDH_compute_key equivalent)
    use openssl::pkey::PKey;
    use openssl::derive::Deriver;
    let my_pkey = PKey::from_ec_key(private_key.clone())?;
    let mut deriver = Deriver::new(&my_pkey)?;
    deriver.set_peer(&public_key)?;
    let shared_secret = deriver.derive_to_vec()?;
    let aes_key = &shared_secret[0..16];
    Ok(aes_key.try_into().unwrap())
}

fn encrypt_aes_128_gcm(
    plaintext: &[u8],
    aad: &[u8],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // From TUTK3rdAESEncryptEx in libTUTKGlobalAPIs.so.
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

    let cipher = Cipher::aes_128_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &aes_key, Some(&aes_iv))?;

    crypter.aad_update(aad)?;

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = crypter.update(plaintext, &mut ciphertext)?;

    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);

    let mut tag = vec![0; 16];
    crypter.get_tag(&mut tag)?;

    Ok((ciphertext, tag))
}

fn make_record_send_p2p_init_handshake_req(session: &IotcSession, server_entry: &ServerEntry) -> Result<Vec<u8>>
{
    // From iotcRecordSendP2PInitHandshakeReq in libIOTCAPIs.so.
    let rsa_encrypted_size = 0;

    let mut packet = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.write_le_u32(constants::RECORD_MAGIC_NUMBER)?;
    packet_cursor.write_u8(1)?;
    packet_cursor.write_u8(RecordType::P2PInitHandshakeReq as u8)?;
    let rsa_encrypted_size_offset = packet_cursor.position();
    packet_cursor.write_le_u16(rsa_encrypted_size)?;
    packet_cursor.write_le_u32(session.session_id)?;

    let der = session.ecdh_key.public_key_to_der()?;
    assert!(der.len() == 0x5b);

    packet_cursor.write(&session.aes_iv)?;
    packet_cursor.write(&der)?;
    packet_cursor.write_u8(0x0)?;
    assert!(packet_cursor.position() == 0x74);

    let aes_key = derive_aes_128_key(&session.ecdh_key, &server_entry.pub_key)?;

   let (ciphertext, tag) = encrypt_aes_128_gcm(&[], &packet[..0x74], aes_key.try_into().unwrap(), session.aes_iv)?;



   packet_cursor.write(&ciphertext)?;
   packet_cursor.write(&tag)?;

   Ok(packet)
}

fn make_hello_server(session: &IotcSession) -> std::io::Result<Vec<u8>> {
    // From HelloServer in libIOTCAPIs.so.

    let content_len = 0x8;
    let packet_flags = 0x2;
    let channel_id = 0x0;
    let sequence_number = 0x0;
    let random_nonce = 0xbcda;

    let mut packet = vec![0; 0x18];
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.write_le_u16(constants::PACKET_MAGIC_NUMBER)?;
    packet_cursor.write_u8(constants::PACKET_VERSION)?;
    packet_cursor.write_u8(packet_flags)?;
    packet_cursor.write_le_u16(content_len)?;
    packet_cursor.write_le_u16(0x0)?;
    packet_cursor.write_le_u16(CmdType::HelloServer as u16)?;
    packet_cursor.write_le_u32(0x3f)?;
    packet_cursor.write_u8(channel_id)?;
    packet_cursor.write_u8(0x0)?;
    packet_cursor.write_le_u32(sequence_number)?; // TODO: feels like some sequence number that is incremented each time. And randomized at start.
    packet_cursor.write_le_u16(random_nonce)?;
    packet_cursor.write_le_u16(0x0)?;

    charlie_cypher::cypher(&mut packet);

    Ok(packet)
}

pub struct IotcSession {
    session_id: u32,
    device_id: [u8; 20],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    nonce1: u16,
    nonce2: u16,
    ecdh_key: EcKey<openssl::pkey::Private>,
}

#[derive(Debug)]
pub struct ServerEntry {
    ip_address: IpAddr,
    port: u16,
    pub_key: PKey<Public>,
}

fn generate_ecdh_key() -> Result<EcKey<openssl::pkey::Private>> {
    // From TUTK3rdECDHCreateKeyPair in libTUTKGlobalAPIs.so:
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let key = EcKey::generate(&group)?;
    Ok(key)
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
            aes_key: [0; 16],
            aes_iv,
            nonce1,
            nonce2,
            ecdh_key: generate_ecdh_key()?,
        })
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

#[derive(Error, Debug)]
enum DecryptError {
    #[error("AuthenticationFailed")]
    AuthenticationFailed,
}

pub fn parse_packet(buffer: &mut [u8]) -> Result<()> {
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
    let _ = reader.read_le_u32()?; // unknown
    let channelId = reader.read_u8()?;
    let _unknow0x15 = reader.read_u8()?; // unknown

    // From FUN_0004a770 in libIOTCAPIs.so
    let cyphered_size = if packet_flags.contains(PacketFlags::CypherExtendHeaderOnly) {
        0x30
    } else {
        packet_size as usize
    };

    if cyphered_size > content.len() {
        return Err(ParseError::InvalidCypheredContentSize.into());
    }

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
        CmdType::P2PInitHandshakeReq | CmdType::P2PInitHandshakeResp => {
            debug!("Received P2P handshake packet");
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

fn decrypt_aes_128_gcm(
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
) -> Result<Vec<u8>, DecryptError> {
    // From TUTK3rdAESDecryptEx in libTUTKGlobalAPIs.so.
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

    let cipher = Cipher::aes_128_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(&aes_iv)).unwrap();

    crypter.aad_update(aad).unwrap();
    crypter.set_tag(tag).unwrap();

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext).unwrap();

    match crypter.finalize(&mut plaintext[count..]) {
        Ok(n) => {
            count += n;
            plaintext.truncate(count);
            Ok(plaintext)
        }
        Err(_) => Err(DecryptError::AuthenticationFailed),
    }
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

pub fn parse(buffer: &mut [u8], session: Option<&IotcSession>) -> Result<Option<Vec<ServerEntry>>> {
    // From iotcRecordHandler in libIOTCAPIs.so / handle_buffer
    let mut buf = Cursor::new(&*buffer);
    let record_magic_number = buf.read_le_u32()?;

    match record_magic_number {
        constants::RECORD_MAGIC_NUMBER => {
            // Process as record
            if let Some(session) = session {
                assert!(buffer.len() >= constants::RECORD_HEADER_SIZE);
                assert!(buffer.len() <= constants::RECORD_PACKET_MAX_SIZE);

                let mut cursor = Cursor::new(&*buffer);
                let _ = cursor.read_le_u32()?; // magic number already read

                let _ = cursor.read_u8()?;
                let record_type: RecordType = cursor.read_u8()?.try_into()?;

                match record_type {
                    RecordType::MasterHandshake => {
                        parse_record_handshake(&buffer, &mut cursor, session).map(Some)
                    }
                    _ => Err(anyhow::anyhow!("Invalid record type")),
                }
            } else {
                Ok(None)
            }
        }
        _ => {
            // Process as packet
            parse_packet(buffer)?;
            Ok(None)
        }
    }
}

pub async fn connect(region: MasterRegion, uid: &str) -> Result<()> {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so

    let mut session_manager = IotcSessionManager::new();
    let session = session_manager.create_session(uid);

    let master_domain_name = get_master_domain_name(region);

    debug!("Master domain name: {}", master_domain_name);

    let send_addr = lookup_host((master_domain_name.as_str(), 10240))
        .await?
        .next()
        .context(format!(
            "Failed to resolve master domain {}",
            master_domain_name
        ))?;

    let record = make_record_send_master_handshake(&session)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&record, send_addr).await?;

    debug!("Socket port after bind: {}", socket.local_addr()?.port());

    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let (usize, _recv_addr) = socket.recv_from(&mut buf).await?;
    buf.truncate(usize);

    assert!(send_addr == _recv_addr);

    debug!("Received response: {:?} {}", buf, buf.len());

    let server_entries = parse(&mut buf, Some(&session))?
        .ok_or_else(|| anyhow::anyhow!("Expected record response"))?;

    let packet = make_hello_server(&session)?;

    for server_entry in &server_entries {
        let target = SocketAddr::from((server_entry.ip_address, server_entry.port));
        socket.send_to(&packet, target).await?;
    }

    debug!("Sent hello server packet to all candidates");

    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let (usize, _recv_addr) = socket.recv_from(&mut buf).await?;
    buf.truncate(usize);

    parse(&mut buf, None)?;

    crate::utils::hexdump(&buf);

    println!("Received response: {:?} {}", buf, buf.len());

    make_record_send_p2p_init_handshake_req(&session, &server_entries[0])?;

    Ok(())
}
