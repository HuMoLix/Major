use std::io::{self, Write};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use colored::Colorize;

mod config;
mod crypto;
mod hardware;
mod tunnel;

const LICENSE_FILE: &str = "license.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct LicenseConfig {
    license_key: String,
    server_ip: String,
}

fn read_saved_config() -> Option<(String, String)> {
    if !Path::new(LICENSE_FILE).exists() {
        return None;
    }
    let mut file = match File::open(LICENSE_FILE) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
        return None;
    }
    let config: LicenseConfig = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(_) => return None,
    };
    Some((config.license_key, config.server_ip))
}

fn save_config(key: &str, ip: &str) -> std::io::Result<()> {
    let config = LicenseConfig {
        license_key: key.to_string(),
        server_ip: ip.to_string(),
    };
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(LICENSE_FILE, content)?;
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Display program version header
    println!("{}", "Major Connection Client v1.2.0".white());

    // 2. Query hardware fingerprint silently
    let device_info = hardware::get_sha256_machine_code();

    // 3. Check for saved license key and server IP locally
    let mut license_key;
    let mut server_ip;
    let mut used_saved = false;

    if let Some((saved_key, saved_ip)) = read_saved_config() {
        println!("{}", format!("[*] Found saved configuration.").white());
        println!("{}", format!("[*] Server IP: {}", saved_ip).white());
        println!("{}", format!("[*] License Key: {}", saved_key).white());
        license_key = saved_key;
        server_ip = saved_ip;
        used_saved = true;
    } else {
        print!("{}", "Enter Server IP (e.g. 192.168.52.129): ".white());
        io::stdout().flush()?;
        let mut ip_input = String::new();
        io::stdin().read_line(&mut ip_input)?;
        server_ip = ip_input.trim().to_string();

        print!("{}", "Enter License Key: ".white());
        io::stdout().flush()?;
        let mut key_input = String::new();
        io::stdin().read_line(&mut key_input)?;
        license_key = key_input.trim().to_string();
    }

    if server_ip.is_empty() {
        return Err("Server IP cannot be empty.".into());
    }
    if license_key.is_empty() {
        return Err("Activation key cannot be empty.".into());
    }

    // 4. Generate dynamic Curve25519 keypair silently
    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);
    let client_pubkey_b64 = BASE64.encode(public_key.as_bytes());

    // 5. Contact activation API silently
    let client = reqwest::Client::new();
    let api_url = format!("http://{}:8000/api/v1/activate", server_ip);

    let mut response = {
        let request_payload = config::ActivationRequest {
            license_key: license_key.to_string(),
            client_pubkey: client_pubkey_b64.clone(),
            device_info: device_info.clone(),
        };
        client.post(&api_url).json(&request_payload).send().await?
    };

    // If saved config failed to activate, prompt user for new credentials
    if used_saved && !response.status().is_success() {
        println!("{}", "[!] Saved configuration is invalid or expired. Re-entering credentials...".yellow());
        
        print!("{}", "Enter Server IP (e.g. 192.168.52.129): ".white());
        io::stdout().flush()?;
        let mut ip_input = String::new();
        io::stdin().read_line(&mut ip_input)?;
        server_ip = ip_input.trim().to_string();

        print!("{}", "Enter License Key: ".white());
        io::stdout().flush()?;
        let mut key_input = String::new();
        io::stdin().read_line(&mut key_input)?;
        license_key = key_input.trim().to_string();
        
        if server_ip.is_empty() {
            return Err("Server IP cannot be empty.".into());
        }
        if license_key.is_empty() {
            return Err("Activation key cannot be empty.".into());
        }

        let api_url_new = format!("http://{}:8000/api/v1/activate", server_ip);
        let request_payload = config::ActivationRequest {
            license_key: license_key.to_string(),
            client_pubkey: client_pubkey_b64,
            device_info: device_info.clone(),
        };
        response = client.post(&api_url_new).json(&request_payload).send().await?;
    }

    if !response.status().is_success() {
        let err_text = response.text().await?;
        return Err(format!("Activation failed: {}", err_text).into());
    }

    let act_resp: config::ActivationResponse = response.json().await?;

    // 6. Decrypt VPN payload silently
    let decrypted_json = crypto::decrypt_payload(&act_resp.nonce, &act_resp.ciphertext, &license_key)?;
    let vpn_config: config::DecryptedConfig = serde_json::from_str(&decrypted_json)?;

    // 7. Validate license expiration silently
    let now_ts = chrono::Utc::now().timestamp();
    if vpn_config.expires_at <= now_ts {
        println!("{}", "[!] License has expired".red());
        return Err("License has expired.".into());
    }

    // Save/persist the successfully activated config locally
    if let Err(e) = save_config(&license_key, &server_ip) {
        println!("{}", format!("[Warning] Failed to save config locally: {}", e).yellow());
    }

    // 8. Connect to VPN
    println!("{}", "[*] Connecting to VPN server...".white());
    tunnel::start_wireguard_tunnel(vpn_config, private_key, license_key, device_info, server_ip).await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    // Enable ANSI escape sequence styling support on Windows Console
    #[cfg(target_os = "windows")]
    let _ = colored::control::set_virtual_terminal(true);

    if let Err(e) = run_client().await {
        eprintln!("{}", format!("\n[ERROR] {}", e).red());
        
        println!("{}", "\nPress Enter to exit...".white());
        let mut exit_buf = String::new();
        let _ = io::stdin().read_line(&mut exit_buf);
        std::process::exit(1);
    }
}
