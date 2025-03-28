use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Client,
};

use serde::Deserialize;

const KMS_URL: &str =
    "https://camera-kms.eu.owletdata.com/kms";

#[derive(Deserialize, Debug)]
pub struct AuthResponse {
    #[serde(rename = "authKey")]
    pub auth_key: String,
    pub password: String,
    pub tutkid: String
}

pub async fn authenticate(client: &Client, access_token: &str, camera_id: &str) -> Result<AuthResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(access_token)?);

    let url = format!("{}/{}", KMS_URL, camera_id);

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await?
        .json::<AuthResponse>()
        .await?;

    if response.tutkid.len() != 20 {
        return Err(anyhow::anyhow!("Invalid tutkid length: {}", response.tutkid.len()));
    }

    Ok(response)
}