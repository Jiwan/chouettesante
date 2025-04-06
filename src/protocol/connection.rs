use openssl::{ec::EcKey, nid::Nid, rsa::{self, Rsa}};
use rand::prelude::*;

use serde::{Deserialize, Serialize};
use serde_json;
use tokio::io::AsyncWriteExt;

use crate::utils::BinaryWriter;

use super::constants;

#[derive(Serialize, Deserialize, Debug)]
enum MasterRegion {
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
        serde_json::to_string(&region).unwrap().to_lowercase(),
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
        rsa_key.public_encrypt(chunk_from, chunk_to, rsa::Padding::NONE).unwrap();
    }

    padded_size
}

pub fn record_send_master_handshake(session_id: u32) -> std::io::Result<()> {
    // From iotcRecordSendMasterHandshake in libIOTCAPIs.so.
    let rsa_encrypted_size = 0;

    let mut packet = Vec::with_capacity(constants::RECORD_PACKET_MAX_SIZE);
    packet.write_le_u16(constants::RECORD_MAGIC_NUMBER)?;
    packet.write_le_u16(0)?;
    BinaryWriter::write_u8(&mut packet, 1)?;
    BinaryWriter::write_u8(&mut packet, 1)?;
    packet.write_le_u16(rsa_encrypted_size)?;
    packet.write_le_u32(session_id)?;

    assert!(packet.len() == constants::RECORD_HEADER_SIZE);
    packet.resize(constants::RECORD_PACKET_MAX_SIZE, 0);

    let mut payload = Vec::with_capacity(0x58);
    payload.write_le_u16(0x204)?;
    BinaryWriter::write_u8(&mut payload, 0x1d)?;
    BinaryWriter::write_u8(&mut payload, 0x0)?;
    
    payload.resize(0x58, 0);


    let encrypted_size = rsa_encrypt(&payload, &mut packet[constants::RECORD_HEADER_SIZE..]);
    packet.truncate(constants::RECORD_HEADER_SIZE + encrypted_size);

    Ok(())
}

pub fn connect(region: MasterRegion, uid: &str) -> () {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so
    let uid: String = uid.to_lowercase();

    let session_id: u32 = 0;
    let nonce1 = rand::random::<u16>();
    let nonce2 = rand::random::<u16>();

    let master_domain_name = get_master_domain_name(region);

    {
        // From TUTK3rdECDHCreateKeyPair in libTUTKGlobalAPIs.so:
        // We might need to use: https://docs.rs/openssl/latest/openssl/ec/struct.EcKey.html#method.generate
        let curve = EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    }
}
