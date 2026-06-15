use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;

const STATIC_SALT: &[u8] = b"commercial_vpn_static_salt_value_12345";

pub fn decrypt_payload(
    nonce_b64: &str,
    ciphertext_b64: &str,
    license_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let nonce_bytes = BASE64.decode(nonce_b64)?;
    let ciphertext_bytes = BASE64.decode(ciphertext_b64)?;

    let mut derived_key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        license_key.as_bytes(),
        STATIC_SALT,
        10000,
        &mut derived_key,
    )?;

    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    let plaintext = String::from_utf8(plaintext_bytes)?;
    Ok(plaintext)
}
