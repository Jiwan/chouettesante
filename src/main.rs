use anyhow::{Context, Result};
use authentication::google;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, Level};
use tracing_subscriber;
mod authentication;

mod charlie_cypher;
mod utils;
mod protocol;

use protocol::iotc_record::{connect, MasterRegion};

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
    // The camera ID could be obtained from firebase using websockets.
    // But for now, this can be fetched manually in owletcare's app.
    pub camera_id: String,
}

fn load_credentials_from_file(file_path: &str) -> Result<Credentials> {
    let file_content =
        std::fs::read_to_string(file_path).context("Failed to read credentials file")?;
    let credentials: Credentials =
        serde_json::from_str(&file_content).context("Failed to parse credentials JSON")?;
    Ok(credentials)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let reqwest_client = Client::new();

    let credentials = load_credentials_from_file("credentials.json")?;
    let response =
        google::authenticate(&reqwest_client, &credentials.email, &credentials.password).await?;

    debug!("Authentication response: {:?}", response);

    let refresh_token_response =
        google::refresh_token(&reqwest_client, &response.refresh_token).await?;

    debug!("Refresh token response: {:?}", refresh_token_response);

    let camera_kms_response = authentication::camera_kms::authenticate(
        &reqwest_client,
        &refresh_token_response.access_token,
        &credentials.camera_id,
    )
    .await?;

    debug!("Camera KMS response: {:?}", camera_kms_response);

    connect(MasterRegion::EU, &camera_kms_response.tutkid).await?;

    Ok(())
}
