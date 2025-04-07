use std::io::{Cursor, Seek};

use openssl::{
    ec::EcKey, encrypt, nid::Nid, rsa::{self, Rsa}
};
use rand::prelude::*;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::net::lookup_host;

use crate::utils::BinaryWriter;

use super::constants;

#[derive(Serialize, Deserialize, Debug)]
pub enum MasterRegion {
    CN,
    EU,
    US,
    ASIA,
}

fn get_master_domain_name(region: MasterRegion) -> String {
    // See GetMasterDomainName in libTUTKGlobalAPIs.so
    let master_type = "c-master";

    // Technically, the suffix is more complicated than this and must be extracted from the nebulaDomainFromLicense you get in SetLicenseKey.
    // But that involves decrypting the licensee key and that feels unnecessary for now.
    // It seems that all suffixes end-up mapping to the same domain name.
    let suffix = "tutk.iotcplatform.com";

    return format!(
        "{}-{}-{}",
        serde_json::to_string(&region).unwrap().trim_matches('"').to_lowercase(),
        master_type,
        suffix
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

pub fn record_send_master_handshake(session_id: u32, uid: [u8;20],  nonce1: u16, aes_seed : [u8; 28]) -> std::io::Result<()> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    let rsa_encrypted_size = 0;

    let mut packet = vec![0; constants::RECORD_PACKET_MAX_SIZE];
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.write_le_u16(constants::RECORD_MAGIC_NUMBER)?;
    packet_cursor.write_le_u16(0)?;
    packet_cursor.write_u8(1)?;
    packet_cursor.write_u8(1)?;
    let rsa_encrypted_size_offset = packet_cursor.position();
    packet_cursor.write_le_u16(rsa_encrypted_size)?;
    packet_cursor.write_le_u32(session_id)?;

    assert!(packet_cursor.position() as usize == constants::RECORD_HEADER_SIZE);

    let mut payload = vec![0; 0x58];
    let mut payload_cursor = Cursor::new(&mut payload);
    payload_cursor.write_le_u16(0x204)?;
    payload_cursor.write_u8(0x1d)?;
    payload_cursor.write_u8(0x0)?;
    payload_cursor.write_le_u16(0x48)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_le_u16(0x100b)?;
    payload_cursor.write_le_u16(0x18)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_le_u16(nonce1)?;
    payload_cursor.write_le_u16(0x0)?;
    payload_cursor.write_bytes(&aes_seed)?;
    payload_cursor.write_bytes(&uid)?;
    // TODO: See GetRealm.

    payload_cursor.write_le_u16(0x0)?; 

    
    let encrypted_size = rsa_encrypt(&payload, &mut packet[constants::RECORD_HEADER_SIZE..]);
    let mut packet_cursor = Cursor::new(&mut packet);
    packet_cursor.set_position(rsa_encrypted_size_offset);
    packet_cursor.write_le_u16(encrypted_size as u16)?;

    packet.truncate(constants::RECORD_HEADER_SIZE + encrypted_size);

    Ok(())
}

pub async fn connect(region: MasterRegion, uid: &str) -> Result<()> {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so
    let uid: String = uid.to_lowercase();

    let session_id: u32 = 0;
    let nonce1 = rand::random::<u16>();
    let nonce2 = rand::random::<u16>();

    let mut aes_seed: [u8; 28] = [0; 28];
    rand::fill(&mut aes_seed);

    let master_domain_name = get_master_domain_name(region);

    {
        // From TUTK3rdECDHCreateKeyPair in libTUTKGlobalAPIs.so:
        // We might need to use: https://docs.rs/openssl/latest/openssl/ec/struct.EcKey.html#method.generate
        let curve = EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    }

    let socket_address = lookup_host((master_domain_name.as_str(), 0))
        .await?
        .next()
        .context(format!(
            "Failed to resolve master domain {}",
            master_domain_name
        ))?;

    Ok(())
}
