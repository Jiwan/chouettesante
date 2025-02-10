use std::cmp::min;

use crate::utils::BufferReader;

use anyhow::{Context, Result};
use thiserror::Error;

use crate::charlie_cypher::decypher;

const RECORD_MAGIC_NUMBER: u16 = 0xcc51;

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
}

use bitflags::bitflags;

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
    let mut buf = BufferReader::new(buffer);
    let record_magic_number = buf.read_le_u16()?;

    match record_magic_number {
        RECORD_MAGIC_NUMBER => parse_record(buffer),
        _ => parse_packet(buffer),
    }
}

fn parse_record(buffer: &mut [u8]) -> Result<()> {
    Ok(())
}

pub fn parse_packet(buffer: &mut [u8]) -> Result<()> {
    let (header, content) = buffer
        .split_at_mut_checked(PACKET_HEADER_SIZE)
        .context(ParseError::InvalidHeaderSize)?;

    decypher(header);

    let mut reader = BufferReader::new(header);
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
    let _ = reader.read_le_u16()?; // unknown

    let cmd_type = reader.read_le_u16()?;

    let cyphered_size = if packet_flags.contains(PacketFlags::CypherExtendHeaderOnly) {
        0x30
    } else {
        packet_size as usize
    };

    if cyphered_size > content.len() {
        return Err(ParseError::InvalidCypheredContentSize.into());
    }

    decypher(&mut content[..cyphered_size]);

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
                let mut reader = BufferReader::new(content);
                let extended_header_size = reader.read_le_u32()? as usize;
                let session1 = reader.read_le_u32()?; // unknown
                let session2 = reader.read_le_u32()?; // unknown

                if session1 == 0 {
                    return Err(ParseError::InvalidSessionId.into());
                }

                // Search for session1 and session2 in gSessionInfo to extract the right session.

                let content = &content[extended_header_size..];
            }
        }
        _ => {}
    }

    Ok(())
}
