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
mod monitor;

const LICENSE_FILE: &str = "license.json";
const CURRENT_VERSION: &str = "1.5.11";

#[derive(serde::Serialize, serde::Deserialize)]
struct LicenseConfig {
    license_key: String,
    server_ip: String,
}

#[derive(serde::Deserialize)]
struct VersionResponse {
    latest_version: String,
}

fn is_version_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let cur_parts = parse(current);
    let lat_parts = parse(latest);
    for i in 0..std::cmp::max(cur_parts.len(), lat_parts.len()) {
        let cur_val = *cur_parts.get(i).unwrap_or(&0);
        let lat_val = *lat_parts.get(i).unwrap_or(&0);
        if lat_val > cur_val {
            return true;
        } else if cur_val > lat_val {
            return false;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    unsafe {
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        IsUserAnAdmin() != 0
    }
}

#[cfg(target_os = "windows")]
fn elevate_process_priority() {
    unsafe {
        extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn SetPriorityClass(h_process: *mut std::ffi::c_void, dw_priority_class: u32) -> i32;
        }
        let handle = GetCurrentProcess();
        let _ = SetPriorityClass(handle, 0x00000080); // HIGH_PRIORITY_CLASS
    }
}

#[cfg(target_os = "windows")]
fn tune_windows_buffers() {
    let _ = std::process::Command::new("reg")
        .args(&[
            "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Afd\\Parameters",
            "/v", "DefaultReceiveWindow",
            "/t", "REG_DWORD",
            "/d", "1048576",
            "/f"
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new("reg")
        .args(&[
            "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Afd\\Parameters",
            "/v", "DefaultSendWindow",
            "/t", "REG_DWORD",
            "/d", "1048576",
            "/f"
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
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
    #[cfg(target_os = "windows")]
    {
        if !is_admin() {
            println!("{}", "[ERROR] Administrator privileges are required to run this client.".red());
            println!("{}", "[ERROR] Please right-click and select \"Run as administrator\".".red());
            println!("{}", "\nPress Enter to exit...".white());
            let mut exit_buf = String::new();
            let _ = io::stdin().read_line(&mut exit_buf);
            std::process::exit(1);
        }
        elevate_process_priority();
        tune_windows_buffers();
        monitor::start_monitor();
    }

    // Check for help arguments
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", format!("Major Connection Client v{}", CURRENT_VERSION).white());
        println!("\nUsage:");
        println!("  client [OPTIONS]");
        println!("\nOptions:");
        println!("  debug, --debug    Enable verbose debug output including server WireGuard config");
        println!("  -h, --help        Show this help message");
        return Ok(());
    }

    // Parse debug flag
    let debug_requested = std::env::args().any(|arg| arg == "--debug" || arg == "debug");
    let mut is_debug = false;

    // 1. Display program version header
    println!("{}", format!("Major Connection Client v{}", CURRENT_VERSION).white());

    // 2. Query hardware fingerprint silently
    let device_info = hardware::get_sha256_machine_code();

    // 3. Check for saved license key and server IP locally
    let mut license_key;
    let mut server_ip;
    let mut used_saved = false;

    if let Some((saved_key, saved_ip)) = read_saved_config() {
        println!("{}", format!("[*] Found saved configuration.").white());
        if is_debug {
            println!("{}", format!("[*] Server IP: {}", saved_ip).white());
            println!("{}", format!("[*] License Key: {}", saved_key).white());
        }
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

    if debug_requested {
        print!("{}", "Enter Debug Validation Code: ".cyan());
        io::stdout().flush()?;
        let mut code_input = String::new();
        io::stdin().read_line(&mut code_input)?;
        let code = code_input.trim().to_string();

        let client_http = reqwest::Client::new();
        let verify_url = format!("http://{}:8000/api/v1/verify-debug", server_ip);
        
        let req_payload = config::VerifyDebugRequest { code };
        match client_http.post(&verify_url).json(&req_payload).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    is_debug = true;
                    println!("{}", "[DEBUG] Debug mode activated successfully.".cyan());
                    println!("{}", format!("[DEBUG] Hardware fingerprint (SHA-256): {}", device_info).cyan());
                    if used_saved {
                        println!("{}", format!("[DEBUG] Saved Server IP: {}", server_ip).cyan());
                        println!("{}", format!("[DEBUG] Saved License Key: {}", license_key).cyan());
                    }
                } else {
                    println!("{}", "[ERROR] Invalid debug validation code.".red());
                    println!("{}", "\nPress Enter to exit...".white());
                    let mut exit_buf = String::new();
                    let _ = io::stdin().read_line(&mut exit_buf);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                println!("{}", format!("[ERROR] Failed to contact server for debug verification: {}", e).red());
                println!("{}", "\nPress Enter to exit...".white());
                let mut exit_buf = String::new();
                let _ = io::stdin().read_line(&mut exit_buf);
                std::process::exit(1);
            }
        }
    }

    // 3.5 Check latest version from server
    println!("{}", "[*] Checking for client updates...".white());
    let client_http = reqwest::Client::new();
    let version_url = format!("http://{}:8000/api/v1/version", server_ip);
    match client_http.get(&version_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(ver_resp) = resp.json::<VersionResponse>().await {
                    if is_version_newer(CURRENT_VERSION, &ver_resp.latest_version) {
                        println!("{}", format!("\n[!] A new version ({}) is available. Current version is {}.", ver_resp.latest_version, CURRENT_VERSION).red());
                        println!("{}", "[!] Please download the latest version to connect. Exiting...".red());
                        println!("{}", "\nPress Enter to exit...".white());
                        let mut exit_buf = String::new();
                        let _ = io::stdin().read_line(&mut exit_buf);
                        std::process::exit(0);
                    } else if is_debug {
                        println!("{}", format!("[DEBUG] Version check passed. Current: {}, Latest: {}", CURRENT_VERSION, ver_resp.latest_version).cyan());
                    }
                }
            }
        }
        Err(e) => {
            println!("{}", format!("[Warning] Version check failed: {}. Continuing connection...", e).yellow());
        }
    }

    // 4. Generate dynamic Curve25519 keypair silently for WireGuard
    let wg_private_key = StaticSecret::random_from_rng(OsRng);
    let wg_public_key = PublicKey::from(&wg_private_key);
    let client_pubkey_b64 = BASE64.encode(wg_public_key.as_bytes());
    if is_debug {
        println!("{}", format!("[DEBUG] Generated ephemeral client Curve25519 public key: {}", client_pubkey_b64).cyan());
    }

    // Generate dynamic RSA keypair for configuration exchange
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::EncodePublicKey;
    
    let mut rng = rand::thread_rng();
    let rsa_bits = 2048;
    if is_debug {
        println!("{}", "[DEBUG] Generating dynamic RSA-2048 keypair...".cyan());
    }
    let rsa_private_key = RsaPrivateKey::new(&mut rng, rsa_bits)
        .map_err(|e| format!("Failed to generate RSA key: {:?}", e))?;
    let rsa_public_key = RsaPublicKey::from(&rsa_private_key);
    
    let rsa_public_key_der = rsa_public_key.to_public_key_der()
        .map_err(|e| format!("Failed to export RSA public key to DER: {:?}", e))?;
    let rsa_pubkey_b64 = BASE64.encode(rsa_public_key_der.as_bytes());
    if is_debug {
        println!("{}", format!("[DEBUG] Generated ephemeral client RSA public key: {}", rsa_pubkey_b64).cyan());
    }

    // 5. Contact activation API silently
    let client = reqwest::Client::new();
    let api_url = format!("http://{}:8000/api/v1/activate", server_ip);
    if is_debug {
        println!("{}", format!("[DEBUG] Sending POST request to: {}", api_url).cyan());
        println!("{}", format!("[DEBUG] Activation Payload: {{ license_key: \"{}\", client_pubkey: \"{}\", rsa_pubkey: \"{}\", device_info: \"{}\" }}", license_key, client_pubkey_b64, rsa_pubkey_b64, device_info).cyan());
    }

    let mut response = {
        let request_payload = config::ActivationRequest {
            license_key: license_key.to_string(),
            client_pubkey: client_pubkey_b64.clone(),
            rsa_pubkey: rsa_pubkey_b64.clone(),
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
        if is_debug {
            println!("{}", format!("[DEBUG] Sending POST request to: {}", api_url_new).cyan());
            println!("{}", format!("[DEBUG] Activation Payload: {{ license_key: \"{}\", client_pubkey: \"{}\", rsa_pubkey: \"{}\", device_info: \"{}\" }}", license_key, client_pubkey_b64, rsa_pubkey_b64, device_info).cyan());
        }

        let request_payload = config::ActivationRequest {
            license_key: license_key.to_string(),
            client_pubkey: client_pubkey_b64.clone(),
            rsa_pubkey: rsa_pubkey_b64.clone(),
            device_info: device_info.clone(),
        };
        response = client.post(&api_url_new).json(&request_payload).send().await?;
    }

    if !response.status().is_success() {
        let err_text = response.text().await?;
        return Err(format!("Activation failed: {}", err_text).into());
    }

    let act_resp: config::ActivationResponse = response.json().await?;
    if is_debug {
        println!("{}", "[DEBUG] Received activation response successfully.".cyan());
        println!("{}", format!("  - Nonce (RSA-encrypted XOR key): {}", act_resp.nonce).cyan());
        println!("{}", format!("  - Ciphertext (XOR-encrypted config): {}", act_resp.ciphertext).cyan());
    }

    // 6. Decrypt VPN payload silently
    let decrypted_json = crypto::decrypt_payload(&act_resp.nonce, &act_resp.ciphertext, &rsa_private_key)?;
    if is_debug {
        println!("{}", format!("[DEBUG] Decrypted VPN Config JSON: {}", decrypted_json).cyan());
    }
    let vpn_config: config::DecryptedConfig = serde_json::from_str(&decrypted_json)?;
    if is_debug {
        println!("{}", "[DEBUG] Parsed Connection Configuration:".cyan());
        println!("{}", format!("  - Server Public Key: {}", vpn_config.server_pubkey).cyan());
        println!("{}", format!("  - Server Endpoint  : {}", vpn_config.endpoint).cyan());
        println!("{}", format!("  - Client Tunnel IP : {}", vpn_config.client_ip).cyan());
        println!("{}", format!("  - DNS Configuration: {:?}", vpn_config.dns).cyan());
        if let Some(dt) = chrono::DateTime::from_timestamp(vpn_config.expires_at, 0) {
            println!("{}", format!("  - Expiration Date  : {} UTC (Timestamp: {})", dt.naive_utc(), vpn_config.expires_at).cyan());
        } else {
            println!("{}", format!("  - Expiration Date  : Timestamp {}", vpn_config.expires_at).cyan());
        }
    }

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
    
    // Exclude the TLS tunnel TCP connection from traffic monitoring stats
    let tls_port = vpn_config.tls_endpoint.as_ref()
        .and_then(|s| s.split(':').last())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8443);
    monitor::set_bypass_server(&server_ip, tls_port);

    tunnel::start_wireguard_tunnel(vpn_config, wg_private_key, license_key, device_info, server_ip, is_debug).await?;

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
