use reqwest::{Client, header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT}};
use serde::{Deserialize, Serialize};
use anyhow::{Result};
use thiserror::Error;

const FIREBASE_API_KEY: &str = "AIzaSyDm6EhV70wudwN3iOSq3vTjtsdGjdFLuuM";
const FIREBASE_URL: &str = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword";

#[derive(Serialize)]
struct AuthRequest {
    #[serde(rename = "clientType")]
    client_type: String,
    email: String,
    password: String,
    #[serde(rename = "returnSecureToken")]
    return_secure_token: bool,
}

#[derive(Deserialize, Debug)]
pub struct AuthResponse {
    kind: Option<String>,

    #[serde(rename = "localId")]
    pub local_id: Option<String>,

    pub email: Option<String>,

    #[serde(rename = "displayName")]
    pub display_name: Option<String>,

    #[serde(rename = "idToken")]
    pub id_token: Option<String>, // JWT token

    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>, // Refresh token

    #[serde(rename = "expiresIn")]
    pub expires_in: Option<String>, // Expiration time in seconds

    pub registered: Option<bool>,

    pub error: Option<AuthError>, // Firebase error response
}

#[derive(Deserialize, Debug)]
pub struct AuthError {
    pub message: String,
}

#[derive(Error, Debug)]
pub enum AuthServiceError {
    #[error("Firebase authentication failed: {0}")]
    FirebaseError(String),

    #[error("Network request failed")]
    RequestError(#[from] reqwest::Error),
}

pub async fn authenticate(email: &str, password: &str) -> Result<AuthResponse> {
    let client = Client::new();
    let request_body = AuthRequest {
        client_type: "CLIENT_TYPE_ANDROID".to_string(),
        email: email.to_string(),
        password: password.to_string(),
        return_secure_token: true,
    };

    // Set up headers
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.034)"));
    headers.insert("X-Android-Package", HeaderValue::from_static("com.owletcare.owletcare"));
    headers.insert("X-Android-Cert", HeaderValue::from_static("2A3BC26DB0B8B0792DBE28E6FFDC2598F9B12B74"));
    headers.insert("X-Firebase-GMPID", HeaderValue::from_static("1:395737756031:android:f1145b652faa5f4a"));
    headers.insert("X-Firebase-Client", HeaderValue::from_static("H4sIAAAAAAAAAKtWykhNLCpJSk0sKVayio7VUSpLLSrOzM9TslIyUqoFAFyivEQfAAAA"));

    let url = format!("{}?key={}", FIREBASE_URL, FIREBASE_API_KEY);

    let response = client
        .post(&url)
        .json(&request_body)
        .headers(headers)
        .send()
        .await?
        .json::<AuthResponse>()
        .await?;

    if let Some(error) = &response.error {
        return Err(AuthServiceError::FirebaseError(error.message.clone()).into());
    }

    Ok(response)
}