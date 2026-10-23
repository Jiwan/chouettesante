// The wire format: the packet and record framing shared by every message,
// the command ids, and the standalone packet parser. Knows nothing about
// sessions.

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use anyhow::{Context, Result};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
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

pub(super) fn read_packet_header_and_split(buffer: &[u8]) -> Result<(PacketHeader, &[u8])> {
    let (header, content) = buffer
        .split_at_checked(constants::PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    let header = read_packet_header(header)?;

    if content.len() != header.content_size as usize {
        return Err(ParseError::InvalidPacketContentSize.into());
    }

    Ok((header, content))
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
// 0x04    1     Version (make_record writes 1)
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

// The parsed facts of a standalone packet (not wrapped in a record), from
// _IOTC_Packet_Handler in libIOTCAPIs.so. Parsing stays pure: the state
// machines apply these facts.
#[derive(Debug, PartialEq)]
pub(super) enum PacketOutcome {
    HelloClient { address: SocketAddr },
    DeviceStatus { online: bool, uid: [u8; 20] },
    Ignored,
}

pub fn parse_packet(buffer: &[u8]) -> Result<PacketOutcome> {
    let buffer_len = buffer.len();
    let (header, content) = buffer
        .split_at_checked(constants::PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    let mut header = header.to_vec();
    decypher(&mut header);

    let packet_header = read_packet_header(&header)?;

    // From FUN_0004a770 in libIOTCAPIs.so: a packet is only processed when
    // the datagram is exactly the header plus the announced content size;
    // anything else is silently dropped.
    if packet_header.content_size as usize + constants::PACKET_HEADER_SIZE != buffer_len {
        warn!(
            "Dropping packet with inconsistent size: {} + 0x{:x} != {}",
            packet_header.content_size, constants::PACKET_HEADER_SIZE, buffer_len
        );
        return Ok(PacketOutcome::Ignored);
    }

    // When the CypherExtendHeaderOnly flag is set, only the first 0x30
    // content bytes are cyphered — but if the content is shorter than that,
    // the whole content is cyphered (charlie_crypt clamps cryptedSize to
    // the buffer size).
    let cyphered_size = if packet_header.flags.contains(PacketFlags::CypherExtendHeaderOnly) {
        0x30.min(content.len())
    } else {
        content.len()
    };

    let mut content = content.to_vec();
    decypher(&mut content[..cyphered_size]);

    // From: _IOTC_Packet_Handler in libIOTCAPIs.so
    let cmd_type_enum = match CmdType::try_from(packet_header.command) {
        Ok(cmd) => cmd,
        Err(_) => {
            warn!("Unknown cmd type: 0x{:04x}", packet_header.command);
            return Ok(PacketOutcome::Ignored);
        }
    };

    let mut reader: Cursor<&[u8]> = Cursor::new(content.as_slice());

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
                let online = packet_header.command == CmdType::DeviceOnlineStatus as u16;
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


// Session data: identity, credentials, the per-peer table and the parsed facts.

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
    fn read_packet_parses_what_write_packet_writes() {
        let mut buffer = [0; 32];
        let mut writer = Cursor::new(buffer.as_mut_slice());

        write_packet(
            &mut writer,
            PacketHeader {
                command: 0x1234,
                channel_id: 0x56,
                flags: 0x78,
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

        let packet = &buffer[..constants::PACKET_HEADER_SIZE + 3];
        let (header, content) = read_packet_header_and_split(packet).unwrap();

        assert_eq!(header.command, 0x1234);
        assert_eq!(header.channel_id, 0x56);
        assert_eq!(header.flags, 0x78);
        assert_eq!(header.command_options, 0xdef0);
        assert_eq!(header.session_id, 0x9abc);
        assert_eq!(header.channel_flags, 0x12);
        assert_eq!(content, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn read_packet_rejects_a_wrong_magic_number() {
        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE];
        packet[0] = 0x99; // Not PACKET_MAGIC_NUMBER.

        let err = read_packet_header(&packet).err().unwrap();
        assert_eq!(err.to_string(), "WrongPacketMagicNumber");
    }

    #[test]
    fn read_packet_accepts_record_embedded_packet_versions() {
        // The master handshake response carries its packet with version
        // 0x1d, not PACKET_VERSION (0x1e): the version byte is never
        // enforced when parsing.
        let mut packet = vec![0u8; constants::PACKET_HEADER_SIZE];
        packet[0..2].copy_from_slice(&constants::PACKET_MAGIC_NUMBER.to_le_bytes());
        packet[2] = 0x1d;

        let (header, content) = read_packet_header_and_split(&packet).unwrap();
        assert_eq!(header.command, 0);
        assert!(content.is_empty());
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
                    flags: 0,
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

        let outcome = parse_packet(&packet).unwrap();
        assert_eq!(outcome, PacketOutcome::HelloClient { address });
    }

    #[test]
    fn read_packet_rejects_an_announced_content_size_mismatch() {
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
        let err = read_packet_header_and_split(packet).err().unwrap();
        assert_eq!(err.to_string(), "InvalidPacketContentSize");
    }

    #[test]
    fn read_record_decrypts_what_make_record_encrypts() {
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
