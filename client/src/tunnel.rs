#![allow(unused_imports)]
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use x25519_dalek::{StaticSecret, PublicKey};
use boringtun::noise::{Tunn, TunnResult};
use crate::config::DecryptedConfig;
use colored::Colorize;

#[cfg(target_os = "windows")]
use wireguard_nt::Adapter;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::FromRawFd;

// ==============================================================================
// Windows Wintun Setup & Configurations
// ==============================================================================

#[cfg(target_os = "windows")]
pub async fn start_wireguard_tunnel(
    config: DecryptedConfig,
    client_private_key: StaticSecret,
    license_key: String,
    device_info: String,
    server_ip: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_pubkey_bytes = BASE64.decode(&config.server_pubkey)?;
    let server_pubkey_arr: [u8; 32] = server_pubkey_bytes.try_into()
        .map_err(|_| "Invalid Server Public Key length")?;
    
    let server_endpoint: SocketAddr = config.endpoint.parse()?;
    let dns_ip = config.dns.first().map(|s| s.as_str()).unwrap_or("223.5.5.5");

    let wireguard = unsafe { wireguard_nt::load() }?;
    let adapter = match wireguard_nt::Adapter::open(&wireguard, "CommercialWG") {
        Ok(a) => a,
        Err(_) => {
            wireguard_nt::Adapter::create(&wireguard, "CommercialVPN", "CommercialWG", None)?
        }
    };
    
    let client_private_bytes: [u8; 32] = client_private_key.to_bytes();
    let client_ipnet: ipnet::IpNet = config.client_ip.parse()?;
    
    let allowed_ips = vec![
        "0.0.0.0/0".parse::<ipnet::IpNet>()?,
    ];

    let interface = wireguard_nt::SetInterface {
        listen_port: None,
        public_key: None,
        private_key: Some(client_private_bytes),
        peers: vec![wireguard_nt::SetPeer {
            public_key: Some(server_pubkey_arr),
            preshared_key: None,
            keep_alive: Some(25),
            endpoint: server_endpoint,
            allowed_ips,
        }],
    };

    adapter.set_config(&interface)?;
    adapter.set_default_route(&[client_ipnet], &interface)?;
    adapter.up()?;

    // Configure DNS via netsh
    let _ = std::process::Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "dnsservers",
            "name=CommercialWG",
            "static", dns_ip, "primary", "validate=no"
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    println!("{}", "[+] VPN Connected successfully (Kernel Mode: WireGuardNT)!".green());
    println!("{}", "[*] Tunnel is running in the background in the Windows Kernel. Press Ctrl+C to disconnect...".white());

    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::channel::<()>(1);
    let countdown_exit_tx = exit_tx.clone();

    // Spawn real-time remaining time countdown task
    let expires_at_ts = config.expires_at;
    let countdown_handle = tokio::spawn(async move {
        use std::io::Write;
        loop {
            let now_ts = chrono::Utc::now().timestamp();
            let diff = expires_at_ts - now_ts;
            if diff > 0 {
                let days = diff / 86400;
                let hours = (diff % 86400) / 3600;
                let minutes = (diff % 3600) / 60;
                let seconds = diff % 60;
                print!("\r{}", format!("[+] Remaining Time: {} days {} hours {} minutes {} seconds  ", days, hours, minutes, seconds).green());
                let _ = std::io::stdout().flush();
            } else {
                for i in (1..=3).rev() {
                    print!("\r{}", format!("[!] License has expired! Exiting in {} seconds...   ", i).red());
                    let _ = std::io::stdout().flush();
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                print!("\r{}", "[!] Exiting...                                             ".red());
                let _ = std::io::stdout().flush();
                let _ = countdown_exit_tx.send(()).await;
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });

    // Spawn background heartbeat task (checks validity once every minute)
    let hb_license_key = license_key.clone();
    let hb_device_info = device_info.clone();
    let hb_server_ip = server_ip.clone();
    let hb_exit_tx = exit_tx.clone();
    let hb_handle = tokio::spawn(async move {
        use std::io::Write;
        let client = reqwest::Client::new();
        let api_url = format!("http://{}:8000/api/v1/heartbeat", hb_server_ip);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let payload = serde_json::json!({
                "license_key": hb_license_key,
                "device_info": hb_device_info
            });
            match client.post(&api_url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        print!("\n\r{}", "[!] License has been banned or invalidated by server! Exiting...   ".red());
                        let _ = std::io::stdout().flush();
                        let _ = hb_exit_tx.send(()).await;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = exit_rx.recv() => {}
    }
    countdown_handle.abort();
    hb_handle.abort();
    println!(); // Print newline to move past the carriage-return line

    println!("{}", "[*] Disconnecting and restoring system routing table...".white());
    
    // Explicitly shut down adapter before dropping it
    let _ = adapter.down();

    println!("{}", "[+] VPN Disconnected. Routing restored.".green());
    Ok(())
}

// ==============================================================================
// Unix (Linux / macOS) Setup & Configurations
// ==============================================================================

#[cfg(target_os = "linux")]
fn create_linux_tun(name: &str) -> io::Result<std::fs::File> {
    use libc::{ioctl, open, O_RDWR, IFF_TUN, IFF_NO_PI};
    
    let fd = unsafe { open(b"/dev/net/tun\0".as_ptr() as *const libc::c_char, O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    
    #[repr(C)]
    struct ifreq {
        ifr_name: [libc::c_char; 16],
        ifr_flags: libc::c_short,
    }
    
    let mut ifr = ifreq {
        ifr_name: [0; 16],
        ifr_flags: (IFF_TUN | IFF_NO_PI) as libc::c_short,
    };
    
    let name_bytes = name.as_bytes();
    let len = std::cmp::min(name_bytes.len(), 15);
    for i in 0..len {
        ifr.ifr_name[i] = name_bytes[i] as libc::c_char;
    }
    
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    let res = unsafe { ioctl(fd, TUNSETIFF, &ifr) };
    if res < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    Ok(file)
}

#[cfg(target_os = "macos")]
fn create_macos_tun() -> io::Result<(std::fs::File, String)> {
    use libc::{socket, connect, ioctl, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL};
    
    let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
    
    #[repr(C)]
    struct ctl_info {
        ctl_id: u32,
        ctl_name: [libc::c_char; 96],
    }
    
    let mut info = ctl_info {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    
    let name = b"com.apple.net.utun_control";
    for i in 0..name.len() {
        info.ctl_name[i] = name[i] as libc::c_char;
    }
    
    let res = unsafe { ioctl(fd, CTLIOCGINFO, &mut info) };
    if res < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    
    #[repr(C)]
    struct sockaddr_ctl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }
    
    let mut addr = sockaddr_ctl {
        sc_len: std::mem::size_of::<sockaddr_ctl>() as u8,
        sc_family: 32, // AF_SYSTEM
        ss_sysaddr: 2, // AF_SYS_CONTROL
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    
    let res = unsafe {
        connect(
            fd,
            &addr as *const sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_ctl>() as u32
        )
    };
    if res < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    
    let mut len = std::mem::size_of::<sockaddr_ctl>() as u32;
    let res = unsafe {
        libc::getsockname(
            fd,
            &mut addr as *mut sockaddr_ctl as *mut libc::sockaddr,
            &mut len
        )
    };
    
    let utun_name = if res >= 0 {
        format!("utun{}", addr.sc_unit)
    } else {
        "utun0".to_string()
    };
    
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    Ok((file, utun_name))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn configure_tun_interface(interface_name: &str, client_ip: &str) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(&["addr", "add", client_ip, "dev", interface_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
            
        let _ = std::process::Command::new("ip")
            .args(&["link", "set", "dev", interface_name, "up"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let _ = std::process::Command::new("ip")
            .args(&["link", "set", "dev", interface_name, "mtu", "1420"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
            
        let _ = std::process::Command::new("ip")
            .args(&["route", "add", "10.0.0.0/24", "dev", interface_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[cfg(target_os = "macos")]
    {
        let clean_ip = client_ip.split('/').next().unwrap_or(client_ip);
        
        let _ = std::process::Command::new("ifconfig")
            .args(&[interface_name, clean_ip, clean_ip, "netmask", "255.255.255.0", "mtu", "1420", "up"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
            
        let _ = std::process::Command::new("route")
            .args(&["add", "-net", "10.0.0.0/24", "-interface", interface_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn start_wireguard_tunnel(
    config: DecryptedConfig,
    client_private_key: StaticSecret,
    license_key: String,
    device_info: String,
    _server_ip: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_pubkey_bytes = BASE64.decode(&config.server_pubkey)?;
    let server_pubkey_arr: [u8; 32] = server_pubkey_bytes.try_into()
        .map_err(|_| "Invalid Server Public Key length")?;
    let server_public_key = PublicKey::from(server_pubkey_arr);
    let server_endpoint: SocketAddr = config.endpoint.parse()?;

    #[cfg(target_os = "linux")]
    let interface_name = "tun0";
    #[cfg(target_os = "linux")]
    let tun_file = create_linux_tun(interface_name)?;

    #[cfg(target_os = "macos")]
    let (tun_file, interface_name_str) = create_macos_tun()?;
    #[cfg(target_os = "macos")]
    let interface_name = &interface_name_str;

    configure_tun_interface(interface_name, &config.client_ip)?;

    let tunn = Tunn::new(
        client_private_key,
        server_public_key,
        None,
        None,
        1,
        None,
    ).map_err(|e| format!("Boringtun Tunn creation failed: {}", e))?;
    
    let tunn = Arc::new(std::sync::Mutex::new(tunn));
    let tun_file = Arc::new(tun_file);

    let domain = match server_endpoint {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let raw_socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    raw_socket.set_send_buffer_size(2 * 1024 * 1024)?;
    raw_socket.set_recv_buffer_size(2 * 1024 * 1024)?;
    
    let bind_addr = match server_endpoint {
        SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>()?,
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>()?,
    };
    raw_socket.bind(&bind_addr.into())?;
    let udp_socket: std::net::UdpSocket = raw_socket.into();
    udp_socket.connect(server_endpoint)?;

    // Loop A: Read from TUN, Encapsulate, Send to UDP
    let tun_file_read = tun_file.clone();
    let udp_send = udp_socket.try_clone()?;
    let tunn_encap = tunn.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut ip_buf = [0u8; 2048];
        let mut udp_buf = [0u8; 2048];
        let mut file = &*tun_file_read;
        loop {
            match file.read(&mut ip_buf) {
                Ok(len) => {
                    if len == 0 {
                        break;
                    }
                    let ip_packet = &ip_buf[..len];
                    let mut tunn = tunn_encap.lock().unwrap();
                    match tunn.encapsulate(ip_packet, &mut udp_buf) {
                        TunnResult::WriteToNetwork(bytes) => {
                            let _ = udp_send.send(bytes);
                        }
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Loop B: Read from UDP, Decapsulate, Write to TUN
    let tun_file_write = tun_file.clone();
    let udp_recv = udp_socket.try_clone()?;
    let tunn_decap = tunn.clone();
    std::thread::spawn(move || {
        use std::io::Write;
        let mut udp_buf = [0u8; 2048];
        let mut ip_buf = [0u8; 2048];
        let mut file = &*tun_file_write;
        loop {
            match udp_recv.recv(&mut udp_buf) {
                Ok(len) => {
                    let packet = &udp_buf[..len];
                    let mut tunn = tunn_decap.lock().unwrap();
                    match tunn.decapsulate(None, packet, &mut ip_buf) {
                        TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                            let _ = file.write_all(bytes);
                        }
                        TunnResult::WriteToNetwork(bytes) => {
                            let _ = udp_recv.send(bytes);
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });

    // Loop C: Handle boringtun timers
    let udp_timer_send = udp_socket.try_clone()?;
    let tunn_timer = tunn.clone();
    tokio::spawn(async move {
        let mut timer_buf = [0u8; 2048];
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let mut tunn = tunn_timer.lock().unwrap();
            match tunn.update_timers(&mut timer_buf) {
                TunnResult::WriteToNetwork(bytes) => {
                    let _ = udp_timer_send.send(bytes);
                }
                _ => {}
            }
        }
    });

    println!("{}", "[+] VPN Connected successfully!".green());
    println!("{}", "[*] Tunnel forwarding is running in the background. Press Ctrl+C to disconnect...".white());

    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::channel::<()>(1);
    let countdown_exit_tx = exit_tx.clone();

    // Spawn real-time remaining time countdown task
    let expires_at_ts = config.expires_at;
    let countdown_handle = tokio::spawn(async move {
        use std::io::Write;
        loop {
            let now_ts = chrono::Utc::now().timestamp();
            let diff = expires_at_ts - now_ts;
            if diff > 0 {
                let days = diff / 86400;
                let hours = (diff % 86400) / 3600;
                let minutes = (diff % 3600) / 60;
                let seconds = diff % 60;
                print!("\r{}", format!("[+] Remaining Time: {} days {} hours {} minutes {} seconds  ", days, hours, minutes, seconds).green());
                let _ = std::io::stdout().flush();
            } else {
                for i in (1..=3).rev() {
                    print!("\r{}", format!("[!] License has expired! Exiting in {} seconds...   ", i).red());
                    let _ = std::io::stdout().flush();
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                print!("\r{}", "[!] Exiting...                                             ".red());
                let _ = std::io::stdout().flush();
                let _ = countdown_exit_tx.send(()).await;
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });

    // Spawn background heartbeat task (checks validity once every minute)
    let hb_license_key = license_key.clone();
    let hb_device_info = device_info.clone();
    let hb_server_ip = server_ip.clone();
    let hb_exit_tx = exit_tx.clone();
    let hb_handle = tokio::spawn(async move {
        use std::io::Write;
        let client = reqwest::Client::new();
        let api_url = format!("http://{}:8000/api/v1/heartbeat", hb_server_ip);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let payload = serde_json::json!({
                "license_key": hb_license_key,
                "device_info": hb_device_info
            });
            match client.post(&api_url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        print!("\n\r{}", "[!] License has been banned or invalidated by server! Exiting...   ".red());
                        let _ = std::io::stdout().flush();
                        let _ = hb_exit_tx.send(()).await;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = exit_rx.recv() => {}
    }
    countdown_handle.abort();
    hb_handle.abort();
    println!(); // Print newline to move past the carriage-return line

    println!("{}", "[*] Disconnecting...".white());
    println!("{}", "[+] VPN Disconnected.".green());
    Ok(())
}
