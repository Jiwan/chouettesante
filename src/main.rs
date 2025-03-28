use anyhow::{Result, Context};
use authentication::google;
use serde::Deserialize;
use tracing::{Level, debug};
use tracing_subscriber;
mod authentication;

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
    // The camera ID could be obtained from firebase using websockets.
    // But for now, this can be fetched manually in owletcare's app.
    pub camera_id: String, 
}

fn load_credentials_from_file(file_path: &str) -> Result<Credentials> {
    let file_content = std::fs::read_to_string(file_path).context("Failed to read credentials file")?;
    let credentials: Credentials =
        serde_json::from_str(&file_content).context("Failed to parse credentials JSON")?;
    Ok(credentials)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).init();

    let credentials = load_credentials_from_file("credentials.json")?;
    let response = google::authenticate(&credentials.email, &credentials.password).await?;

    debug!("Authentication response: {:?}", response);

    let refresh_token_response = google::refresh_token(&response.refresh_token).await?;

    debug!("Refresh token response: {:?}", refresh_token_response);

    let camera_kms_response =
        authentication::camera_kms::authenticate(&refresh_token_response.access_token, &credentials.camera_id).await?;

    debug!("Camera KMS response: {:?}", camera_kms_response);

    Ok(())
}
