use sha2::Digest;

#[cfg(target_os = "windows")]
fn get_hardware_info(command: &str, args: &[&str]) -> String {
    if let Ok(output) = std::process::Command::new(command).args(args).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut result = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if lower == "serialnumber" || lower == "processorid" {
                continue;
            }
            result.push(trimmed.to_string());
        }
        return result.join(":");
    }
    String::new()
}

#[cfg(target_os = "windows")]
pub fn get_sha256_machine_code() -> String {
    let motherboard = get_hardware_info("wmic", &["baseboard", "get", "serialnumber"]);
    let cpu = get_hardware_info("wmic", &["cpu", "get", "processorid"]);
    let disk = get_hardware_info("wmic", &["diskdrive", "get", "serialnumber"]);
    
    let raw_hardware_string = format!("MB:{}|CPU:{}|DISK:{}", motherboard, cpu, disk);
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_hardware_string.as_bytes());
    let hash_result = hasher.finalize();
    format!("{:x}", hash_result)
}

#[cfg(target_os = "linux")]
pub fn get_sha256_machine_code() -> String {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string();
    
    let cpu_info = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("model name") || line.starts_with("cpu MHz") || line.starts_with("Processor"))
        .collect::<Vec<&str>>()
        .join("\n");
        
    let raw_hardware_string = format!("MACHINE_ID:{}|CPU:{}", machine_id, cpu_info);
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_hardware_string.as_bytes());
    let hash_result = hasher.finalize();
    format!("{:x}", hash_result)
}

#[cfg(target_os = "macos")]
pub fn get_sha256_machine_code() -> String {
    let serial = if let Ok(output) = std::process::Command::new("sh")
        .args(&["-c", "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber | awk -F'\"' '{print $4}'"])
        .output()
    {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "MOCK-MACOS-SERIAL".to_string()
    };
    
    let raw_hardware_string = format!("MAC_SERIAL:{}", serial);
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_hardware_string.as_bytes());
    let hash_result = hasher.finalize();
    format!("{:x}", hash_result)
}
