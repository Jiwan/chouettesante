// The record layer: crafting the outgoing records and parsing the
// incoming ones, one helper per message. The send side crafts last
// minute from the session; the receive side is a pure parse producing
// ParseOutcome facts for the state machines to apply.

use std::{
    io::{Cursor, Read, Seek},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use openssl::pkey::PKey;

use anyhow::{Context, Result, bail};
use tracing::{debug, warn};

use super::{
    constants,
    crypto::decrypt_aes_128_gcm,
    get_realm,
    session::{P2PPeer, ParseOutcome, ServerEntry, SessionCore},
    wire::{
        CmdType, PacketHeader, PacketOutcome, ParseError, RecordEncryption, RecordType,
        PACKET_HEADER_SIZE, make_record, parse_packet, write_packet,
    },
};

use crate::{
    charlie_cypher,
    utils::{BinaryReader, BinaryWriter},
};

pub(super) fn make_record_send_master_handshake(session: &SessionCore) -> Result<Vec<u8>> {
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

pub(super) fn make_record_send_p2p_init_handshake_req(
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

pub(super) fn make_hello_server(session: &SessionCore) -> Result<Vec<u8>> {
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

pub(super) fn make_record_send_p2p_keep_alive(record_sid: u32) -> Result<Vec<u8>> {
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


// Record parsing: the receive side, one helper per incoming record.

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
    let mut reader: Cursor<&[u8]> = Cursor::new(buffer);
    reader.set_position(constants::RECORD_HEADER_SIZE as u64);
    let record_sid = reader.read_le_u32()?;

    debug!("Keepalive received (record sid 0x{:08x})", record_sid);

    Ok(record_sid)
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


// The following structs mirror Session.field_0x740 in libIOTCAPIs.so: the main connection state
// machine, as a typestate.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_handshake_uses_the_common_record_layout() {
        let session = SessionCore::new(0x12345678, "ABCDEFGHIJKLMNOPQRST");

        let record = make_record_send_master_handshake(&session).unwrap();

        assert_eq!(record.len(), constants::RECORD_HEADER_SIZE + 0x100);
        assert_eq!(&record[0..4], &constants::RECORD_MAGIC_NUMBER.to_le_bytes());
        assert_eq!(record[4], 1);
        assert_eq!(record[5], RecordType::MasterHandshake as u8);
        assert_eq!(&record[6..8], &0x100_u16.to_le_bytes());
        assert_eq!(&record[8..12], &session.session_id.to_le_bytes());
    }

}
