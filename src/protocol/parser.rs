use std::{io::Cursor};

use crate::utils::BinaryReader;

use anyhow::{Context, Result};
use thiserror::Error;

use bitflags::bitflags;
use super::constants;
use crate::charlie_cypher::decypher;
use super::iotc_record;

const PACKET_MAGIC_NUMBER: u16 = 0x0204;
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

pub fn parse(buffer: &mut [u8]) -> Result<()> {
    let mut buf = Cursor::new(&mut *buffer);
    let record_magic_number = buf.read_le_u32()?;

    match record_magic_number {
        constants::RECORD_MAGIC_NUMBER => iotc_record::parse(buffer, [0; 16], [0; 12]),
        _ => parse_packet(buffer),
    }
}

pub fn parse_packet(buffer: &mut [u8]) -> Result<()> {
    let (header, content) = buffer
        .split_at_mut_checked(PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    decypher(header);

    let mut reader = Cursor::new(header);
    let magic_number = reader.read_le_u16()?;

    if magic_number != PACKET_MAGIC_NUMBER {
        return Err(ParseError::WrongPacketMagicNumber.into());
    }

    let version = reader.read_u8()?;

    if version != 0x1d {
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
    match cmd_type {
        0x408 => {
            if packet_flags.contains(PacketFlags::UnknownFlag0x4) {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if content.len() < 0x0c {
                return Err(ParseError::InvalidCypheredContentSize.into());
            }

            if !packet_flags.contains(PacketFlags::UnknownFlag0x8) {
                // TODO
            } else {
                let mut reader: Cursor<&mut [u8]> = Cursor::new(content);
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
            }
        }
        _ => {}
    }

    Ok(())
}


// As a stream: https://docs.rs/ringbuf/latest/ringbuf/
// Supplied to a SslStream: https://docs.rs/openssl/0.10.71/openssl/ssl/index.html