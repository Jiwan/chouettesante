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

    let packet_type = reader.read_u8()?;
    let packet_size = reader.read_le_u32()?;

    let cyphered_size = if (packet_type & 0x1) != 0 {
        0x30
    } else {
        packet_size as usize
    };

    if cyphered_size > content.len() {
        return Err(ParseError::InvalidCypheredContentSize.into());
    }

    decypher(&mut content[..cyphered_size]);

    Ok(())
}
