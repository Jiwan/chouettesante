use openssl::{ec::EcKey, nid::Nid};
use std::rand;

use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug)]
enum MasterRegion {
    CN,
    EU,
    US,
    ASIA,
}

pub fn get_master_domain_name(region: MasterRegion) -> String {
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
