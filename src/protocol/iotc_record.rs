use std::{
    any,
    collections::HashMap,
    io::{Cursor, Read, Seek},
};

use openssl::{
    ec::EcKey, encrypt, nid::Nid, pkey::PKey, rsa::{self, Rsa}, symm::{Cipher, Crypter, Mode}
};
use rand::prelude::*;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use tokio::net::{lookup_host, UdpSocket};
use tracing::{debug, info, warn};

use crate::utils::BinaryReader;
use crate::utils::BinaryWriter;

use super::constants;

#[repr(u8)]
enum RecordType {
    Handshake = 0x1,
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
            0x1 => Ok(RecordType::Handshake),
            _ => Err(RecordConversionError::InvalidRecordType),
        }
    }
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

pub fn make_record_send_master_handshake(session: &IotcSession) -> std::io::Result<Vec<u8>> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    let rsa_encrypted_size = 0;

    let mut packet = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.write_le_u32(constants::RECORD_MAGIC_NUMBER)?;
    packet_cursor.write_u8(1)?;
    packet_cursor.write_u8(RecordType::Handshake as u8)?;
    let rsa_encrypted_size_offset = packet_cursor.position();
    packet_cursor.write_le_u16(rsa_encrypted_size)?;
    packet_cursor.write_le_u32(session.session_id)?;

    assert!(packet_cursor.position() as usize == constants::RECORD_HEADER_SIZE);

    let mut payload = vec![0; 0x58];
    let mut payload_cursor = Cursor::new(&mut payload);
    payload_cursor.write_le_u16(constants::HANDSHAKE_MAGIC_NUMBER)?;
    payload_cursor.write_u8(0x1d)?;
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

struct IotcSession {
    session_id: u32,
    device_id: [u8; 20],
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    nonce1: u16,
    nonce2: u16,
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
) -> Result<()>
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
    assert!(handshake_magic_number == constants::HANDSHAKE_MAGIC_NUMBER);
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

    for _ in 0..entry_count {
        let entry_type = payload_cursor.read_le_u16()?;
        let entry_size = payload_cursor.read_le_u16()? as u64;
        let entry_offset = payload_cursor.position();

        match entry_type {
            9 => {
                /* server entries or something */
                let server_count = entry_size / 0x6C;

                for _ in 0..server_count {
                    let test = payload_cursor.read_le_u16()?;
                    info!("Server test: {}", test);
                    let _ = payload_cursor.read_le_u16()?;
                    let ip_address = payload_cursor.read_le_u32()?;
                    let _ = payload_cursor.read_le_u64()?;
                    
                    let mut der_key = [0; 0x5c];
                    payload_cursor.read_exact(&mut der_key)?;
                    let pub_key = PKey::public_key_from_der(& der_key)?;

                    debug!("Server IP: {}.{}.{}.{}, pub_key: {:?}",
                        ip_address & 0xFF,
                        (ip_address >> 8) & 0xFF,
                        (ip_address >> 16) & 0xFF,
                        (ip_address >> 24) & 0xFF,
                        pub_key
                    );
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

    Ok(())
}

pub fn parse(buffer: &[u8], session: &IotcSession) -> Result<()> {
    // From iotcRecordHandler in libIOTCAPIs.so.
    assert!(buffer.len() >= constants::RECORD_HEADER_SIZE);
    assert!(buffer.len() <= constants::RECORD_PACKET_MAX_SIZE);

    let mut cursor = Cursor::new(buffer);
    let record_magic_number = cursor.read_le_u32()?;

    assert!(record_magic_number == constants::RECORD_MAGIC_NUMBER);

    let _ = cursor.read_u8()?;
    let record_type: RecordType = cursor.read_u8()?.try_into()?;

    match record_type {
        RecordType::Handshake => {
            parse_record_handshake(&buffer, &mut cursor, session)?;
        }
        _ => return Err(anyhow::anyhow!("Invalid record type")),
    }
    Ok(())
}

pub async fn connect(region: MasterRegion, uid: &str) -> Result<()> {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so

    let mut session_manager = IotcSessionManager::new();
    let session = session_manager.create_session(uid);

    let master_domain_name = get_master_domain_name(region);

    {
        // From TUTK3rdECDHCreateKeyPair in libTUTKGlobalAPIs.so:
        // We might need to use: https://docs.rs/openssl/latest/openssl/ec/struct.EcKey.html#method.generate
        let curve = EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    }

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

    let mut buf = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let (usize, recv_addr) = socket.recv_from(&mut buf).await?;
    buf.truncate(usize);

    assert!(send_addr == recv_addr);

    println!("Received response: {:?} {}", buf, buf.len());

    parse(&buf, &session)?;

    Ok(())
}
