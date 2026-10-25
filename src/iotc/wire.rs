// The wire format: the packet and record framing shared by every message,
// the command ids, and the packet parser. Knows nothing about sessions.

use std::{
    borrow::Cow,
    io::{Cursor, Read, Seek},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use anyhow::{Context, Result};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use openssl::pkey::{PKey, Public};
use thiserror::Error;
use tracing::{debug, warn};

use super::{
    constants,
    crypto::{decrypt_aes_128_gcm, encrypt_aes_128_gcm, rsa_encrypt, rsa_encrypted_size},
};

use crate::{
    charlie_cypher::decypher,
    utils::{BinaryReader, BinaryWriter},
};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(super) struct PacketFlags: u8 {
        const CypherExtendHeaderOnly = 0b0001;
        const UnknownFlag0x2 = 0b0010;
        const UnknownFlag0x4 = 0b0100;
        const UnknownFlag0x8 = 0b1000;
    }
}

pub(super) struct PacketHeader {
    pub(super) command: u16,
    pub(super) channel_id: u8,
    pub(super) flags: PacketFlags,
    pub(super) command_options: u16, // Speculative field.
    pub(super) session_id: u16,      // Speculative field.
    pub(super) channel_flags: u8,    // Speculative field.
    pub(super) content_size: u16
}


#[derive(Error, Debug)]
pub(super) enum ParseError {
    #[error("InvalidHeaderSize")]
    InvalidHeaderSize,
    #[error("WrongPacketMagicNumber")]
    WrongPacketMagicNumber,
    #[error("WrongRecordMagicNumber")]
    WrongRecordMagicNumber,
    #[error("InvalidCypheredContentSize")]
    InvalidCypheredContentSize,
    #[error("InvalidPacketContentSize")]
    InvalidPacketContentSize,
    #[error("InvalidRecordSize")]
    InvalidRecordSize,
    #[error("WrongFlagType")]
    WrongFlagType,
    #[error("InvalidSessionId")]
    InvalidSessionId,
    #[error("InvalidChannelId")]
    InvalidChannelId,
}

#[repr(u8)]
#[derive(Debug)]
pub(super) enum RecordType {
    MasterHandshake = 0x1,
    P2PInitHandshakeReq = 0x2,
    // From the switch in iotcRecordHandler in libIOTCAPIs.so: only types
    // 1, 3, 4 and 5 are parsed on the client side. Type 2 records are
    // send-only.
    P2PInitHandshakeResp = 0x3,
    KeyPush = 0x4,
    KeepAlive = 0x5,
}

#[derive(Error, Debug)]
pub(super) enum RecordConversionError {
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

pub(super) enum RecordEncryption {
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

#[repr(u16)]
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
pub(super) enum CmdType {
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
pub(super) fn write_packet<WriteContent>(
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
    packet_writer.write_u8(header.flags.bits())?;

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

pub(super) fn read_packet_header(buffer: &[u8]) -> Result<PacketHeader> {
    if buffer.len() < constants::PACKET_HEADER_SIZE {
        return Err(ParseError::InvalidHeaderSize.into());
    }

    let mut reader = Cursor::new(buffer);
    let magic_number = reader.read_le_u16()?;

    if magic_number != constants::PACKET_MAGIC_NUMBER {
        return Err(ParseError::WrongPacketMagicNumber.into());
    }

    let _version = reader.read_u8()?;
    let flags = reader.read_u8()?;
    let content_size = reader.read_le_u16()?;

    let _unknown0x6 = reader.read_le_u16()?; // unknown
    let command = reader.read_le_u16()?;
    let command_options = reader.read_le_u16()?;
    let session_id = reader.read_le_u16()?;
    let channel_id = reader.read_u8()?;
    let channel_flags = reader.read_u8()?;

    Ok(
        PacketHeader {
            command,
            channel_id,
            flags: PacketFlags::from_bits_retain(flags),
            command_options,
            session_id,
            channel_flags,
            content_size,
        })
}

pub(super) enum PacketCypher {
    // A standalone packet: the header is charlie-cyphered, and so is the
    // content — fully, or only its first 0x30 bytes when the
    // CypherExtendHeaderOnly flag is set (charlie_crypt clamps the cyphered
    // size to the buffer size).
    Charlie,
    Plaintext,
}

pub(super) fn write_record<WriteExtendedHeader, WritePayload>(
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

pub(super) struct RecordHeader {
    pub(super) record_type: RecordType,
    pub(super) session_id: u32,
}

// How to turn a record body back into its payload: the inverse of
// RecordEncryption. Rsa is missing on purpose: incoming records are only
// ever AES-GCM encrypted with the session or peer keys (or not encrypted
// at all, for keepalives), and no RSA private key is available anyway.
pub(super) enum RecordDecryption {
    Aes128Gcm { key: [u8; 16], iv: [u8; 12] },
    Unencrypted,
}

impl RecordDecryption {
    fn decrypt(self, body: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm { key, iv } => {
                if body.len() < constants::RECORD_AES_TAG_SIZE {
                    return Err(ParseError::InvalidRecordSize.into());
                }
                let (ciphertext, tag) =
                    body.split_at(body.len() - constants::RECORD_AES_TAG_SIZE);
                Ok(decrypt_aes_128_gcm(ciphertext, aad, tag, key, iv)?)
            }
            Self::Unencrypted => Ok(body.to_vec()),
        }
    }
}

// 0x0c bytes, little-endian, followed by the record body:
//
// Offset  Size  Field
// 0x00    4     Magic number (RECORD_MAGIC_NUMBER, 0xcc51)
// 0x04    1     Version (write_record writes 1)
// 0x05    1     Record type (RecordType)
// 0x06    2     Record size (the body size, ciphertext and tag included)
// 0x08    4     Session id
// 0x0c    ...   Record body: AES-128-GCM ciphertext + 0x10 tag (the
//               record header above is the AAD), or plaintext for the
//               unencrypted keepalive. The records received from the
//               servers carry no extended header.
//
// The inverse of write_record: parses and validates the record header,
// checks the datagram is exactly the header plus the announced size, and
// returns the header with the decrypted payload.
pub(super) fn read_record_header_and_decrypt(
    buffer: &[u8],
    decryption: RecordDecryption,
) -> Result<(RecordHeader, Vec<u8>)> {
    let mut reader = Cursor::new(buffer);

    let magic_number = reader.read_le_u32()?;

    if magic_number != constants::RECORD_MAGIC_NUMBER {
        return Err(ParseError::WrongRecordMagicNumber.into());
    }

    let _version = reader.read_u8()?;
    let record_type: RecordType = reader.read_u8()?.try_into()?;
    let record_size = reader.read_le_u16()? as usize;
    let session_id = reader.read_le_u32()?;
    assert_eq!(reader.position() as usize, constants::RECORD_HEADER_SIZE);

    // A record datagram is exactly the header plus the announced size.
    if buffer.len() != constants::RECORD_HEADER_SIZE + record_size {
        return Err(ParseError::InvalidRecordSize.into());
    }

    let header = RecordHeader {
        record_type,
        session_id,
    };

    debug!(
        "Record: type {:?}, session id 0x{:08x}, body {} bytes",
        header.record_type, header.session_id, record_size
    );

    // Layout: header (aad) | body (ciphertext + tag, or plaintext)
    // Size:     0x0c       |   ...
    let aad = &buffer[..constants::RECORD_HEADER_SIZE];
    let body = &buffer[constants::RECORD_HEADER_SIZE..];
    let payload = decryption.decrypt(body, aad)?;

    Ok((header, payload))
}

// A P2P server candidate, as carried by the type 9 entries of the master
// handshake response (cmd 0x100c).
#[derive(Debug)]
pub struct ServerEntry {
    pub(super) ip_address: IpAddr,
    pub(super) port: u16,
    pub(super) pub_key: PKey<Public>,
}

#[derive(Debug)]
pub(super) enum PacketOutcome {
    HelloClient { address: SocketAddr },
    DeviceStatus { online: bool, uid: [u8; 20] },
    P2PHandshake {
        nonce2: u16,
        uid: [u8; 20],
        record_sid: u32,
        keepalive_interval: u16,
    },
    ServerList {
        nonce1: u16,
        uid: [u8; 20],
        servers: Vec<ServerEntry>,
    },
    Ignored,
}

fn parse_server_list(reader: &mut Cursor<&[u8]>) -> Result<PacketOutcome> {
    let nonce1 = reader.read_le_u16()?;
    let _ = reader.read_le_u16()?;
    let uid = reader.read_bytes::<20>()?;
    reader.seek(std::io::SeekFrom::Start(0x3a))?;
    let entry_count = reader.read_le_u16()?;
    assert!(entry_count != 0);
    let mut servers = vec![];
    for _ in 0..entry_count {
        let entry_type = reader.read_le_u16()?;
        let entry_size = reader.read_le_u16()? as u64;
        let entry_offset = reader.position();

        match entry_type {
            9 => {
                /* server entries or something */
                let server_count = entry_size / 0x6C;

                for _ in 0..server_count {
                    let _ = reader.read_le_u16()?;
                    let port = reader.read_be_u16()?;
                    let ip_address: u32 = reader.read_be_u32()?;
                    let _ = reader.read_le_u64()?;

                    let mut der_key = [0; 0x5c];
                    reader.read_exact(&mut der_key)?;
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
                let _unknown1 = reader.read_le_u16()?;
                let _unknown2 = reader.read_le_u16()?;
                let _unknown3 = reader.read_le_u16()?;
                // It looks like those 3 short are reversed: unknown3, unknown2, unknown1.
            }
            _ => {
                warn!("Unknown entry type: {}", entry_type);
            }
        }

        reader.set_position(entry_offset + entry_size);
    }

    Ok(PacketOutcome::ServerList {
        nonce1,
        uid,
        servers,
    })
}

fn parse_p2p_handshake(reader: &mut Cursor<&[u8]>) -> Result<PacketOutcome> {
    if reader.get_ref().len() < 0x36 {
        return Err(ParseError::InvalidPacketContentSize.into());
    }
    let nonce2 = reader.read_le_u16()?;
    let _ = reader.read_le_u16()?;
    let record_sid = reader.read_le_u32()?;
    let uid = reader.read_bytes::<20>()?;
    reader.set_position(0x34);
    let keepalive_interval = reader.read_le_u16()?;

    Ok(PacketOutcome::P2PHandshake {
        nonce2,
        uid,
        record_sid,
        keepalive_interval,
    })
}

fn parse_device_status(reader: &mut Cursor<&[u8]>, packet_header: PacketHeader) -> Result<PacketOutcome> {
    if reader.get_ref().len() < 20 {
        return Ok(PacketOutcome::Ignored);
    }

    let online = packet_header.command == CmdType::DeviceOnlineStatus as u16;
    let uid = reader.read_bytes::<20>()?;
    Ok(PacketOutcome::DeviceStatus { online, uid })
}

fn parse_hello_client(mut reader: Cursor<&[u8]>) -> Result<PacketOutcome> {
    if reader.get_ref().len() < 16 {
        return Ok(PacketOutcome::Ignored);
    }

    let _ = reader.read_le_u16()?;
    let port = reader.read_be_u16()?;
    let address: u32 = reader.read_be_u32()?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(address)), port);
    let _ = reader.read_le_u64()?;
    Ok(PacketOutcome::HelloClient { address })
}

pub(super) fn parse_packet(buffer: &[u8], cypher: PacketCypher) -> Result<PacketOutcome> {
    let (header, content) = buffer
        .split_at_checked(constants::PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    // Charlie decyphers in place and needs an owned buffer; Plaintext
    // borrows the datagram slices as-is.
    let mut header = match cypher {
        PacketCypher::Charlie => Cow::Owned(header.to_vec()),
        PacketCypher::Plaintext => Cow::Borrowed(header),
    };
    let mut content= match cypher {
        PacketCypher::Charlie => Cow::Owned(content.to_vec()),
        PacketCypher::Plaintext => Cow::Borrowed(content),
    };

    if let PacketCypher::Charlie = cypher {
        decypher(header.to_mut());
    }

    let packet_header = read_packet_header(&header)?;

    if let PacketCypher::Charlie = cypher {
        let cyphered_size = if packet_header.flags.contains(PacketFlags::CypherExtendHeaderOnly) {
            0x30.min(content.len())
        } else {
            content.len()
        };

        decypher(&mut content.to_mut()[..cyphered_size]);
    }

    // A packet is exactly the header plus the announced content size.
    if content.len() != packet_header.content_size as usize {
        warn!(
            "Packet content size mismatch: announced {}, got {}",
            packet_header.content_size,
            content.len()
        );
        return Err(ParseError::InvalidPacketContentSize.into());
    }

    // From: _IOTC_Packet_Handler in libIOTCAPIs.so
    let cmd_type_enum = match CmdType::try_from(packet_header.command) {
        Ok(cmd) => cmd,
        Err(_) => {
            warn!("Unknown cmd type: 0x{:04x}", packet_header.command);
            return Ok(PacketOutcome::Ignored);
        }
    };

    let mut reader: Cursor<&[u8]> = Cursor::new(&content[..]);

    match cmd_type_enum {
        CmdType::UnknownCmd0x408 => {
            if packet_header.flags.contains(PacketFlags::UnknownFlag0x4) {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if content.len() < 0x0c {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if !packet_header.flags.contains(PacketFlags::UnknownFlag0x8) {
                // TODO
            } else {
                let extended_header_size = reader.read_le_u32()? as usize;
                let session1 = reader.read_le_u32()?; // unknown
                let session2 = reader.read_le_u32()?; // unknown

                if session1 == 0 {
                    return Err(ParseError::InvalidSessionId.into());
                }

                // Search for session1 and session2 in gSessionInfo to extract the right session.

                if packet_header.channel_id >= 0x20 {
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
        CmdType::P2PInit | CmdType::P2PInitHandshakeReq => {
            debug!("Received P2P handshake packet");
        }
        CmdType::P2PHandshake => {
            return parse_p2p_handshake(&mut reader);
        }
        CmdType::P2PInitHandshakeResp => {
            return parse_server_list(&mut reader);
        }
        CmdType::KeyPush => {
            debug!("Received P2P session packet");
        }
        CmdType::DeviceOfflineStatus | CmdType::DeviceOnlineStatus => {
            return parse_device_status(&mut reader, packet_header);
        }
        CmdType::HelloServer => {
            debug!("Received HelloServer packet");
        }
        CmdType::HelloClient => {
            return parse_hello_client(reader);
        }
    }

    Ok(PacketOutcome::Ignored)
}

#[cfg(test)]
mod tests {
    use super::*;

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
                flags: PacketFlags::from_bits_retain(0x78),
                command_options: 0xdef0,
                session_id: 0x9abc,
                channel_flags: 0x12,
                content_size: 3,
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
                flags: PacketFlags::empty(),
                command_options: 0,
                session_id: 0,
                channel_flags: 0,
                content_size: 2,
            },
            |writer| {
                writer.write_u8(0)?;
                Ok(())
            },
            2,
        )
        .unwrap();
    }

    #[test]
    fn read_packet_header_parses_what_write_packet_writes() {
        let mut buffer = [0; 32];
        let mut writer = Cursor::new(buffer.as_mut_slice());

        write_packet(
            &mut writer,
            PacketHeader {
                command: 0x1234,
                channel_id: 0x56,
                flags: PacketFlags::from_bits_retain(0x78),
                command_options: 0xdef0,
                session_id: 0x9abc,
                channel_flags: 0x12,
                content_size: 3,
            },
            |writer| {
                writer.write_bytes(&[0xaa, 0xbb, 0xcc])?;
                Ok(())
            },
            3,
        )
        .unwrap();

        let header = read_packet_header(&buffer[..constants::PACKET_HEADER_SIZE]).unwrap();

        assert_eq!(header.command, 0x1234);
        assert_eq!(header.channel_id, 0x56);
        assert_eq!(header.flags.bits(), 0x78);
        assert_eq!(header.command_options, 0xdef0);
        assert_eq!(header.session_id, 0x9abc);
        assert_eq!(header.channel_flags, 0x12);
        assert_eq!(header.content_size, 3);
    }

    #[test]
    fn read_packet_rejects_a_wrong_magic_number() {
        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE];
        packet[0] = 0x99; // Not PACKET_MAGIC_NUMBER.

        let err = read_packet_header(&packet).err().unwrap();
        assert_eq!(err.to_string(), "WrongPacketMagicNumber");
    }

    #[test]
    fn parse_packet_accepts_record_embedded_packet_versions() {
        // The master handshake response carries its packet with version
        // 0x1d, not PACKET_VERSION (0x1e): the version byte is never
        // enforced when parsing.
        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE];
        packet[0..2].copy_from_slice(&constants::PACKET_MAGIC_NUMBER.to_le_bytes());
        packet[2] = 0x1d;

        let outcome = parse_packet(&packet, PacketCypher::Plaintext).unwrap();
        assert!(matches!(outcome, PacketOutcome::Ignored));
    }

    #[test]
    fn parse_packet_accepts_unexpected_packet_versions() {
        // The P2P servers answer our HelloServer with a standalone packet
        // carrying version 0x1f: the version byte is logged but the packet
        // is still parsed.
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);

        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE + 16];
        {
            let mut writer = Cursor::new(packet.as_mut_slice());
            write_packet(
                &mut writer,
                PacketHeader {
                    command: CmdType::HelloClient as u16,
                    channel_id: 0,
                    flags: PacketFlags::empty(),
                    command_options: 0,
                    session_id: 0,
                    channel_flags: 0,
                    content_size: 16,
                },
                |writer| {
                    writer.write_le_u16(2)?; // Probably the af type.
                    writer.write_be_u16(5678)?;
                    writer.write_be_u32(u32::from(Ipv4Addr::new(1, 2, 3, 4)))?;
                    writer.write_le_u64(0)?; // unknown
                    Ok(())
                },
                16,
            )
            .unwrap();
        }
        packet[2] = 0x1f;
        crate::charlie_cypher::cypher(&mut packet);

        let outcome = parse_packet(&packet, PacketCypher::Charlie).unwrap();
        let PacketOutcome::HelloClient { address: parsed } = outcome else {
            panic!("Expected a HelloClient outcome");
        };
        assert_eq!(parsed, address);
    }

    #[test]
    fn parse_packet_rejects_an_announced_content_size_mismatch() {
        let mut buffer = [0; 32];
        let mut writer = Cursor::new(buffer.as_mut_slice());

        write_packet(
            &mut writer,
            PacketHeader {
                command: 0,
                channel_id: 0,
                flags: PacketFlags::empty(),
                command_options: 0,
                session_id: 0,
                channel_flags: 0,
                content_size: 3,
            },
            |writer| {
                writer.write_bytes(&[0xaa, 0xbb, 0xcc])?;
                Ok(())
            },
            3,
        )
        .unwrap();

        // Truncate the content: the announced size no longer matches.
        let packet = &buffer[..constants::PACKET_HEADER_SIZE + 2];
        let err = parse_packet(packet, PacketCypher::Plaintext)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "InvalidPacketContentSize");
    }

    #[test]
    fn parse_packet_parses_a_p2p_handshake_packet() {
        // A P2PHandshake packet (cmd 0x218) as embedded in the type 3
        // handshake response record.
        let uid = [0x42; 20];

        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE + 0x36];
        {
            let mut writer = Cursor::new(packet.as_mut_slice());
            write_packet(
                &mut writer,
                PacketHeader {
                    command: CmdType::P2PHandshake as u16,
                    channel_id: 0,
                    flags: PacketFlags::empty(),
                    command_options: 0,
                    session_id: 0,
                    channel_flags: 0,
                    content_size: 0x36,
                },
                |writer| {
                    writer.write_le_u16(0x1234)?; // nonce2
                    writer.write_le_u16(0)?;
                    writer.write_le_u32(0xdeadbeef)?; // record sid
                    writer.write_bytes(&uid)?;
                    writer.write_bytes(&[0; 0x34 - 0x1c])?; // pad up to offset 0x34
                    writer.write_le_u16(257)?; // keepalive interval
                    Ok(())
                },
                0x36,
            )
            .unwrap();
        }

        let outcome = parse_packet(&packet, PacketCypher::Plaintext).unwrap();
        let PacketOutcome::P2PHandshake {
            nonce2,
            uid: parsed_uid,
            record_sid,
            keepalive_interval,
        } = outcome
        else {
            panic!("Expected a P2PHandshake outcome");
        };
        assert_eq!(nonce2, 0x1234);
        assert_eq!(parsed_uid, uid);
        assert_eq!(record_sid, 0xdeadbeef);
        assert_eq!(keepalive_interval, 257);
    }

    #[test]
    fn parse_packet_decyphers_only_the_extended_header_of_a_charlie_packet() {
        // With CypherExtendHeaderOnly, only the first 0x30 content bytes
        // are cyphered (charlie_crypt clamps the cyphered size to the
        // buffer size); the rest of the content stays plaintext. The
        // keepalive interval sits at content offset 0x34 — past the
        // cyphered prefix — so it proves the tail was left alone.
        let uid = [0x42; 20];
        const CONTENT_SIZE: usize = 0x36;

        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE + CONTENT_SIZE];
        {
            let mut writer = Cursor::new(packet.as_mut_slice());
            write_packet(
                &mut writer,
                PacketHeader {
                    command: CmdType::P2PHandshake as u16,
                    channel_id: 0,
                    flags: PacketFlags::CypherExtendHeaderOnly,
                    command_options: 0,
                    session_id: 0,
                    channel_flags: 0,
                    content_size: CONTENT_SIZE as u16,
                },
                |writer| {
                    writer.write_le_u16(0x1234)?; // nonce2
                    writer.write_le_u16(0)?;
                    writer.write_le_u32(0xdeadbeef)?; // record sid
                    writer.write_bytes(&uid)?;
                    writer.write_bytes(&[0; 0x34 - 0x1c])?; // pad up to offset 0x34
                    writer.write_le_u16(257)?; // keepalive interval
                    Ok(())
                },
                CONTENT_SIZE,
            )
            .unwrap();
        }

        // Cypher only what the server would cypher: the header plus the
        // first 0x30 content bytes.
        let cyphered_size = constants::PACKET_HEADER_SIZE + 0x30;
        crate::charlie_cypher::cypher(&mut packet[..cyphered_size]);

        let outcome = parse_packet(&packet, PacketCypher::Charlie).unwrap();
        let PacketOutcome::P2PHandshake {
            keepalive_interval, ..
        } = outcome
        else {
            panic!("Expected a P2PHandshake outcome");
        };
        assert_eq!(keepalive_interval, 257);
    }

    #[test]
    fn read_record_decrypts_what_write_record_encrypts() {
        let key = [0x42; 16];
        let iv = [0x24; 12];
        const PAYLOAD_SIZE: usize = 5;
        const RECORD_SIZE: usize = PAYLOAD_SIZE + constants::RECORD_AES_TAG_SIZE;

        let record = write_record(
            RecordType::P2PInitHandshakeResp,
            0x12345678,
            RECORD_SIZE,
            PAYLOAD_SIZE,
            RecordEncryption::Aes128Gcm { key, iv },
            |_| Ok(()),
            |writer| {
                writer.write_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee])?;
                Ok(())
            },
        )
        .unwrap();

        let (header, payload) =
            read_record_header_and_decrypt(&record, RecordDecryption::Aes128Gcm { key, iv }).unwrap();

        assert!(matches!(
            header.record_type,
            RecordType::P2PInitHandshakeResp
        ));
        assert_eq!(header.session_id, 0x12345678);
        assert_eq!(payload, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    }

    #[test]
    fn read_record_reads_unencrypted_records() {
        let mut record = vec![0u8; constants::RECORD_HEADER_SIZE + 0xc];
        let mut writer = Cursor::new(record.as_mut_slice());
        writer.write_le_u32(constants::RECORD_MAGIC_NUMBER).unwrap();
        writer.write_u8(1).unwrap();
        writer.write_u8(RecordType::KeepAlive as u8).unwrap();
        writer.write_le_u16(0xc).unwrap();
        writer.write_le_u32(0xffff).unwrap();
        writer.write_le_u32(0xdeadbeef).unwrap();

        let (header, body) = read_record_header_and_decrypt(&record, RecordDecryption::Unencrypted).unwrap();

        assert!(matches!(header.record_type, RecordType::KeepAlive));
        assert_eq!(header.session_id, 0xffff);
        assert_eq!(Cursor::new(&body).read_le_u32().unwrap(), 0xdeadbeef);
    }

    #[test]
    fn read_record_rejects_a_wrong_magic_number() {
        let record = [0u8; constants::RECORD_HEADER_SIZE];

        let err = read_record_header_and_decrypt(&record, RecordDecryption::Unencrypted)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "WrongRecordMagicNumber");
    }

    #[test]
    fn read_record_rejects_a_size_mismatch() {
        // The announced record size does not match the datagram length.
        let mut record = vec![0u8; constants::RECORD_HEADER_SIZE + 0xc];
        record[0..4].copy_from_slice(&constants::RECORD_MAGIC_NUMBER.to_le_bytes());
        record[5] = RecordType::KeepAlive as u8;
        record[6..8].copy_from_slice(&0x0b_u16.to_le_bytes()); // Announced 0x0b, actual 0x0c.

        let err = read_record_header_and_decrypt(&record, RecordDecryption::Unencrypted)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "InvalidRecordSize");
    }
}
