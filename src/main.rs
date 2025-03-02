use anyhow::{Result, Context};
use authentication::google;
use serde::Deserialize;
mod authentication;

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

fn load_credentials_from_file(file_path: &str) -> Result<Credentials> {
    let file_content = std::fs::read_to_string(file_path).context("Failed to read credentials file")?;
    let credentials: Credentials =
        serde_json::from_str(&file_content).context("Failed to parse credentials JSON")?;
    Ok(credentials)
}

#[tokio::main]
async fn main() -> Result<()> {
    let credentials = load_credentials_from_file("credentials.json")?;
    let response = google::authenticate(&credentials.email, &credentials.password).await?;

    println!("Response: {:?}", response);

    let refresh_token_response = google::refresh_token(&response.refresh_token).await?;

    println!("Refresh token response: {:?}", refresh_token_response);

    Ok(())
}
