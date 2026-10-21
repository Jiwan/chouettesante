// The IOTC rendezvous protocol, mirroring libIOTCAPIs.so. The wire
// framing lives in wire.rs, the session data in session.rs, the record
// layer in records.rs and the connection state machine in machine.rs;
// this module keeps the constants, the crypto helpers, the master
// discovery, the session table and the connect() driver.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::net::{lookup_host, UdpSocket};
use tracing::debug;

use crate::utils::SocketUtils;

mod constants;
mod crypto;
mod machine;
mod records;
mod session;
mod wire;

pub use records::parse;

use machine::{ConnectionAction, Session};

#[derive(Serialize, Deserialize, Debug)]
pub enum MasterRegion {
    CN,
    EU,
    US,
    ASIA,
}

pub(super) fn get_realm() -> &'static str {
    // Technically, the realm is more complicated than this and must be extracted from the nebulaDomainFromLicense you get in SetLicenseKey.
    // But that involves decrypting the licensee key and that feels unnecessary for now.
    // It seems that all suffixes end-up mapping to the same domain name.
    return "tutk.iotcplatform.com";
}

fn get_master_domain_name(region: MasterRegion) -> String {
    // See GetMasterDomainName in libTUTKGlobalAPIs.so
    let master_type = "c-master";

    return format!(
        "{}-{}-{}",
        serde_json::to_string(&region)
            .unwrap()
            .trim_matches('"')
            .to_lowercase(),
        master_type,
        get_realm()
    );
}


// Record crafting: the send side, one helper per outgoing record.

pub struct IotcSessionManager {
    sessions: HashMap<u32, Session>,
    session_id_counter: u32,
}

impl IotcSessionManager {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_id_counter: 0,
        }
    }

    fn create_session(&mut self, uid: &str, auth_key: [u8; 8]) -> Session {
        self.session_id_counter += 1;
        let session_id = self.session_id_counter;
        Session::new(session_id, uid, auth_key)
    }

    fn take_session(&mut self, session_id: u32) -> Option<Session> {
        self.sessions.remove(&session_id)
    }
}

// The auth_key is the 8-byte camera-kms auth key, passed by the Owlet app to
// IOTC_Connect_ByUIDEx as UIDExtraData (connectWithAuth in its CameraSDK).
pub async fn connect(region: MasterRegion, uid: &str, auth_key: &str) -> Result<()> {
    // From IOTC_Connect_UDP_Inner in libIOTCAPIs.so.

    let auth_key: [u8; 8] = auth_key
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("The auth key must be exactly 8 bytes"))?;

    let mut session_manager = IotcSessionManager::new();
    let session = session_manager.create_session(uid, auth_key);

    let master_domain_name = get_master_domain_name(region);

    debug!("Master domain name: {}", master_domain_name);

    // From AddUDPQueryDeviceInfoTask: the handshake goes to every resolved
    // master address.
    let master_addrs: Vec<SocketAddr> = lookup_host((master_domain_name.as_str(), 10240))
        .await
        .context("Failed to resolve the master domain")?
        .collect();

    if master_addrs.is_empty() {
        bail!("Failed to resolve master domain {}", master_domain_name);
    }

    debug!("Master addresses: {:?}", master_addrs);

    let mut session = session.start_connection(master_addrs)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut reception_buffer = vec![0; constants::RECORD_PACKET_MAX_SIZE];

    // Entry action of the MasterHandshake state: contact the masters right
    // away instead of waiting for the first tick.
    let mut actions = session.on_tick()?;

    loop {
        for action in actions {
            match action {
                ConnectionAction::Send { data, to } => {
                    debug!("Sending {} bytes to {}", data.len(), to);
                    socket.send_to(&data, to).await?;
                }
                ConnectionAction::Finished => {
                    debug!("Connection finished, exiting loop");
                    return Ok(());
                }
            }
        }

        actions = match socket
            .rcv_from_timeout(&mut reception_buffer, Duration::from_millis(500))
            .await
        {
            Ok(Ok((data, from))) => {
                debug!("Received {} bytes from {}", data.len(), from);

                let old_state = session.to_string();

                let (next, actions) = session.on_datagram(data, from)?;
                session = next;

                let new_state = session.to_string();
                if (old_state != new_state) {
                    debug!("State transition: {} -> {}", old_state, new_state);
                }

                actions
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => session.on_tick()?,
        };
    }
}
