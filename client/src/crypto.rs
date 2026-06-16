use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub fn decrypt_payload(
    nonce_b64: &str,      // RSA-encrypted XOR key
    ciphertext_b64: &str, // XOR-encrypted config
    private_key: &rsa::RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_xor_key = BASE64.decode(nonce_b64)?;
    let ciphertext_bytes = BASE64.decode(ciphertext_b64)?;

    // 1. Decrypt XOR key using RSA private key
    use rsa::Pkcs1v15Encrypt;
    let xor_key = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_xor_key)
        .map_err(|e| format!("RSA decryption failed: {:?}", e))?;

    // 2. Decrypt ciphertext using XOR with the key
    let plaintext_bytes = xor_crypt(&ciphertext_bytes, &xor_key);
    let plaintext = String::from_utf8(plaintext_bytes)?;
    Ok(plaintext)
}

fn xor_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}
