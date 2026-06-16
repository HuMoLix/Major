use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ActivationRequest {
    pub license_key: String,
    pub client_pubkey: String,
    pub rsa_pubkey: String,
    pub device_info: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct ActivationResponse {
    pub status: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DecryptedConfig {
    pub server_pubkey: String,
    pub endpoint: String,
    pub client_ip: String,
    pub dns: Vec<String>,
    pub expires_at: i64,
}
