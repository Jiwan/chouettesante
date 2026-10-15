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
    crypto::{encrypt_aes_128_gcm, rsa_encrypt, rsa_encrypted_size},
};

use crate::{
    charlie_cypher::decypher,
    utils::{BinaryReader, BinaryWriter},
};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct PacketFlags: u8 {
        const CypherExtendHeaderOnly = 0b0001;
        const UnknownFlag0x2 = 0b0010;
        const UnknownFlag0x4 = 0b0100;
        const UnknownFlag0x8 = 0b1000;
    }
}

pub(super) struct PacketHeader {
    pub(super) command: u16,
    pub(super) channel_id: u8,
    pub(super) flags: u8,
    pub(super) command_options: u16, // Speculative field.
    pub(super) session_id: u16,      // Speculative field.
    pub(super) channel_flags: u8,    // Speculative field.
}


#[derive(Error, Debug)]
pub(super) enum ParseError {
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

#[repr(u8)]
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

pub(super) fn make_record<WriteExtendedHeader, WritePayload>(
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
    if packet_size as usize + constants::PACKET_HEADER_SIZE != buffer_len {
        warn!(
            "Dropping packet with inconsistent size: {} + 0x{:x} != {}",
            packet_size, constants::PACKET_HEADER_SIZE, buffer_len
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
