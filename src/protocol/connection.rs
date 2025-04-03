use openssl::{ec::EcKey, nid::Nid, rsa::Rsa};
use rand::prelude::*;

use serde::{Deserialize, Serialize};
use serde_json;

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

fn rsa_encrypt() {
    let rsa_key = Rsa::public_key_from_pem(constants::PUB_RSA_KEY.as_bytes()).unwrap();
    rsa_key.size();
}

pub fn recordSendMasterHandshake(session_id: u32) -> () {
    let rsa_encrypted_size = 0;

    let mut packet = Vec::with_capacity(constants::RECORD_PACKET_MAX_SIZE);
    packet.write_le_u16(constants::RECORD_MAGIC_NUMBER)?;
    packet.write_u8(1)?;
    packet.write_u8(1)?;
    packet.write_le_u16(rsa_encrypted_size)?;
    packet.write_le_u32(session_id)?;
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
