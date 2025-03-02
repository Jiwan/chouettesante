use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT},
    Client,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::time::Duration;

const FIREBASE_API_KEY: &str = "AIzaSyDm6EhV70wudwN3iOSq3vTjtsdGjdFLuuM";
const VERIFY_PASSWORD_URL: &str =
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword";
const SECURE_TOKEN_URL: &str = "https://securetoken.googleapis.com/v1/token";

fn deserialize_duration_from_string<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let seconds = str.parse::<u64>().map_err(serde::de::Error::custom)?;
    Ok(Duration::from_secs(seconds))
}

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
    kind: String,

    #[serde(rename = "localId")]
    pub local_id: String,

    pub email: String,

    #[serde(rename = "displayName")]
    pub display_name: String,

    #[serde(rename = "idToken")]
    pub id_token: String,

    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    #[serde(rename = "expiresIn", deserialize_with="deserialize_duration_from_string")]
    pub expires_in: Duration,

    pub registered: bool,

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

fn fill_firebase_headers(headers: &mut HeaderMap) {
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.220922.034)",
        ),
    );
    headers.insert(
        "X-Android-Package",
        HeaderValue::from_static("com.owletcare.owletcare"),
    );
    headers.insert(
        "X-Android-Cert",
        HeaderValue::from_static("2A3BC26DB0B8B0792DBE28E6FFDC2598F9B12B74"),
    );
    headers.insert(
        "X-Firebase-GMPID",
        HeaderValue::from_static("1:395737756031:android:f1145b652faa5f4a"),
    );
    headers.insert(
        "X-Firebase-Client",
        HeaderValue::from_static(
            "H4sIAAAAAAAAAKtWykhNLCpJSk0sKVayio7VUSpLLSrOzM9TslIyUqoFAFyivEQfAAAA",
        ),
    );
}

pub async fn authenticate(email: &str, password: &str) -> Result<AuthResponse> {
    let client = Client::new();
    let request_body = AuthRequest {
        client_type: "CLIENT_TYPE_ANDROID".to_string(),
        email: email.to_string(),
        password: password.to_string(),
        return_secure_token: true,
    };

    let mut headers = HeaderMap::new();
    fill_firebase_headers(&mut headers);

    let url = format!("{}?key={}", VERIFY_PASSWORD_URL, FIREBASE_API_KEY);

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


#[derive(Serialize)]
struct RefreshTokenRequest {
    #[serde(rename = "grantType")]
    grant_type: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
pub struct RefreshTokenResponse {
    access_token: String,
    #[serde(deserialize_with = "deserialize_duration_from_string")]
    expires_in: Duration,
    id_token: String,
    project_id: String,
    refresh_token: String,
    token_type: String,
    user_id: String,
}

pub async fn refresh_token(refresh_token: &str) -> Result<RefreshTokenResponse> {
    let client = Client::new();

    let request_body = RefreshTokenRequest {
        grant_type: "refresh_token".to_string(),
        refresh_token: refresh_token.to_string(),
    };

    let mut headers = HeaderMap::new();
    fill_firebase_headers(&mut headers);

    let url = format!("{}?key={}", SECURE_TOKEN_URL, FIREBASE_API_KEY);

    let response = client
        .post(&url)
        .json(&request_body)
        .headers(headers)
        .send()
        .await?
        .json::<RefreshTokenResponse>()
        .await?;

    Ok(response)
}