#![allow(unused_imports)]
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use x25519_dalek::{StaticSecret, PublicKey};
use boringtun::noise::{Tunn, TunnResult};
use crate::config::DecryptedConfig;
use colored::Colorize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(target_os = "windows")]
use wireguard_nt::Adapter;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::FromRawFd;

use std::sync::atomic::{AtomicU64, Ordering};

pub static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RECV: AtomicU64 = AtomicU64::new(0);
pub static TRAFFIC_LIMIT: AtomicU64 = AtomicU64::new(0);
pub static TRAFFIC_USED: AtomicU64 = AtomicU64::new(0);

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ==============================================================================
// UDP-over-TLS Local Proxy Helper Functions
// ==============================================================================

async fn setup_tls_proxy_if_needed(
    tls_endpoint_opt: &Option<String>,
    original_endpoint: SocketAddr,
    is_debug: bool,
) -> Result<(SocketAddr, Option<tokio::task::JoinHandle<()>>), Box<dyn std::error::Error>> {
    if let Some(ref tls_endpoint) = tls_endpoint_opt {
        if is_debug {
            println!("{}", format!("[*] TLS proxy mode enabled. Target: {}", tls_endpoint).cyan());
        }
        let local_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let local_port = local_udp.local_addr()?.port();
        let local_endpoint = format!("127.0.0.1:{}", local_port).parse::<SocketAddr>()?;
        if is_debug {
            println!("{}", format!("[*] Bound local proxy UDP to: {}", local_endpoint).cyan());
        }

        let tls_ep = tls_endpoint.clone();
        let handle = tokio::spawn(async move {
            run_local_tls_bridge(local_udp, tls_ep, is_debug).await;
        });
        Ok((local_endpoint, Some(handle)))
    } else {
        Ok((original_endpoint, None))
    }
}

async fn run_local_tls_bridge(local_udp: tokio::net::UdpSocket, tls_endpoint: String, is_debug: bool) {
    let local_udp = std::sync::Arc::new(local_udp);
    loop {
        if is_debug {
            println!("{}", format!("[*] Connecting to TLS proxy at {}...", tls_endpoint).cyan());
        }
        match connect_and_bridge(&local_udp, &tls_endpoint, is_debug).await {
            Ok(_) => {
                if is_debug {
                    println!("{}", "[*] TLS bridge session finished.".cyan());
                }
            }
            Err(e) => {
                eprintln!("{}", format!("[!] TLS bridge connection error: {}. Reconnecting in 3 seconds...", e).yellow());
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }
    }
}

async fn connect_and_bridge(
    local_udp: &std::sync::Arc<tokio::net::UdpSocket>,
    tls_endpoint: &str,
    is_debug: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = tls_endpoint.parse()?;
    let host = addr.ip().to_string();

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let tls_stream = tokio_connector.connect(&host, tcp).await?;
    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    if is_debug {
        println!("{}", "[+] TLS tunnel established successfully!".green());
    }

    let wintun_port = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0));

    // TLS -> UDP
    let local_udp_write = local_udp.clone();
    let wintun_port_write = wintun_port.clone();
    let t1 = tokio::spawn(async move {
        let mut len_buf = [0u8; 2];
        let mut pkt_buf = [0u8; 2048];
        loop {
            if tls_read.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len > pkt_buf.len() {
                break;
            }
            if tls_read.read_exact(&mut pkt_buf[..len]).await.is_err() {
                break;
            }
            BYTES_RECV.fetch_add(len as u64, Ordering::Relaxed);
            let port = wintun_port_write.load(std::sync::atomic::Ordering::Relaxed);
            if port != 0 {
                let dest = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    port,
                );
                if is_debug {
                    println!("[DEBUG TLS->UDP] Forwarded packet of len {} to Wintun at port {}", len, port);
                }
                let _ = local_udp_write.send_to(&pkt_buf[..len], dest).await;
            } else {
                if is_debug {
                    println!("[DEBUG TLS->UDP] Received packet of len {} but Wintun port not yet registered", len);
                }
            }
        }
    });

    // UDP -> TLS
    let local_udp_read = local_udp.clone();
    let wintun_port_read = wintun_port.clone();
    let t2 = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match local_udp_read.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if is_debug {
                        println!("[DEBUG UDP->TLS] Received packet of len {} from Wintun at {}", len, src);
                    }
                    wintun_port_read.store(src.port(), std::sync::atomic::Ordering::Relaxed);
                    BYTES_SENT.fetch_add(len as u64, Ordering::Relaxed);
                    let len_bytes = (len as u16).to_be_bytes();
                    if tls_write.write_all(&len_bytes).await.is_err() {
                        break;
                    }
                    if tls_write.write_all(&buf[..len]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if is_debug {
                        println!("[DEBUG UDP->TLS] recv_from error: {:?}", e);
                    }
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }

    Ok(())
}

// ==============================================================================
// Windows Wintun Setup & Configurations
// ==============================================================================

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MIB_IPFORWARDROW {
    pub dwForwardDest: u32,
    pub dwForwardMask: u32,
    pub dwForwardPolicy: u32,
    pub dwForwardNextHop: u32,
    pub dwForwardIfIndex: u32,
    pub dwForwardType: u32,
    pub dwForwardProto: u32,
    pub dwForwardAge: u32,
    pub dwForwardNextHopAS: u32,
    pub dwForwardMetric1: u32,
    pub dwForwardMetric2: u32,
    pub dwForwardMetric3: u32,
    pub dwForwardMetric4: u32,
    pub dwForwardMetric5: u32,
}

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
extern "system" {
    pub fn GetBestRoute(
        dwDestAddr: u32,
        dwSourceAddr: u32,
        pBestRoute: *mut MIB_IPFORWARDROW,
    ) -> u32;
}

#[cfg(target_os = "windows")]
fn add_server_bypass_route(server_ip_str: &str, is_debug: bool) -> Option<(String, String)> {
    use std::net::Ipv4Addr;
    let ip: Ipv4Addr = server_ip_str.parse().ok()?;
    let ip_u32 = u32::from_ne_bytes(ip.octets());
    let mut route = unsafe { std::mem::zeroed::<MIB_IPFORWARDROW>() };
    let ret = unsafe { GetBestRoute(ip_u32, 0, &mut route) };
    if ret == 0 {
        let gateway = Ipv4Addr::from(route.dwForwardNextHop.swap_bytes());
        let gateway_str = gateway.to_string();
        let if_index = route.dwForwardIfIndex;
        if is_debug {
            println!("[*] Adding host route to server {} via gateway {} (interface {}) to bypass VPN...", server_ip_str, gateway_str, if_index);
        }
        
        let _ = std::process::Command::new("route")
            .args(&[
                "add",
                server_ip_str,
                "mask",
                "255.255.255.255",
                &gateway_str,
                "metric",
                "1",
                "if",
                &if_index.to_string()
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        
        Some((server_ip_str.to_string(), gateway_str))
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn remove_server_bypass_route(server_ip: &str, gateway: &str, is_debug: bool) {
    if is_debug {
        println!("[*] Removing bypass route for server {}...", server_ip);
    }
    let _ = std::process::Command::new("route")
        .args(&[
            "delete",
            server_ip,
            "mask",
            "255.255.255.255",
            gateway
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(target_os = "windows")]
pub async fn start_wireguard_tunnel(
    config: DecryptedConfig,
    client_private_key: StaticSecret,
    license_key: String,
    device_info: String,
    server_ip: String,
    is_debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Reset/Initialize traffic counters
    BYTES_SENT.store(0, Ordering::Relaxed);
    BYTES_RECV.store(0, Ordering::Relaxed);
    TRAFFIC_LIMIT.store(config.traffic_limit.unwrap_or(0), Ordering::Relaxed);
    TRAFFIC_USED.store(config.traffic_used.unwrap_or(0), Ordering::Relaxed);

    let server_pubkey_bytes = BASE64.decode(&config.server_pubkey)?;
    let server_pubkey_arr: [u8; 32] = server_pubkey_bytes.try_into()
        .map_err(|_| "Invalid Server Public Key length")?;
    
    let server_endpoint: SocketAddr = config.endpoint.parse()?;
    let (actual_peer_endpoint, bridge_handle) = setup_tls_proxy_if_needed(&config.tls_endpoint, server_endpoint, is_debug).await?;
    let dns_ip = config.dns.first().map(|s| s.as_str()).unwrap_or("223.5.5.5");

    let wireguard = unsafe { wireguard_nt::load() }?;
    let adapter = match wireguard_nt::Adapter::open(&wireguard, "CommercialWG") {
        Ok(a) => a,
        Err(_) => {
            wireguard_nt::Adapter::create(&wireguard, "CommercialWG", "CommercialWG", None)?
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
            endpoint: actual_peer_endpoint,
            allowed_ips,
        }],
    };

    let bypass_route_info = if config.tls_endpoint.is_some() {
        add_server_bypass_route(&server_ip, is_debug)
    } else {
        None
    };

    adapter.set_config(&interface)?;
    adapter.set_default_route(&[client_ipnet], &interface)?;
    adapter.up()?;

    // Configure MTU dynamically
    let mtu = if config.tls_endpoint.is_some() { 1360 } else { 1420 };
    let _ = std::process::Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "subinterface",
            "CommercialWG",
            &format!("mtu={}", mtu),
            "store=active"
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

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

    // Block UDP 443 outgoing to force HTTP/3 (QUIC) fallback to TCP for traffic monitoring
    let _ = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            "name=CommercialVPN_BlockQUIC",
            "dir=out", "action=block", "protocol=UDP", "remoteport=443"
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
        let mut last_bytes = 0;
        loop {
            let now_ts = chrono::Utc::now().timestamp();
            let diff = expires_at_ts - now_ts;
            if diff > 0 {
                let days = diff / 86400;
                let hours = (diff % 86400) / 3600;
                let minutes = (diff % 3600) / 60;
                let seconds = diff % 60;

                let sent = BYTES_SENT.load(Ordering::Relaxed);
                let recv = BYTES_RECV.load(Ordering::Relaxed);
                let current_bytes = sent + recv;
                let speed_bytes = if current_bytes >= last_bytes { current_bytes - last_bytes } else { 0 };
                last_bytes = current_bytes;

                let limit = TRAFFIC_LIMIT.load(Ordering::Relaxed);
                let used = TRAFFIC_USED.load(Ordering::Relaxed);

                let traffic_str = if limit > 0 {
                    let total_used = used + current_bytes;
                    let remaining_bytes = if limit > total_used { limit - total_used } else { 0 };
                    format!("Traffic Left: {} / {}", format_bytes(remaining_bytes), format_bytes(limit))
                } else {
                    format!("Traffic Used: {}", format_bytes(used + current_bytes))
                };

                let speed_str = format_bytes(speed_bytes);

                print!(
                    "\r{}",
                    format!(
                        "[+] Remaining Time: {}d {}h {}m {}s | {} | Session: {} ({}/s)   ",
                        days, hours, minutes, seconds,
                        traffic_str,
                        format_bytes(current_bytes),
                        speed_str
                    ).green()
                );
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
            let top_10 = crate::monitor::get_top_10_apps();
            let app_traffic_json: Vec<serde_json::Value> = top_10.iter().map(|(app, bytes)| {
                serde_json::json!({
                    "app": app,
                    "bytes": bytes
                })
            }).collect();
            let payload = serde_json::json!({
                "license_key": hb_license_key,
                "device_info": hb_device_info,
                "app_traffic": app_traffic_json
            });
            #[derive(serde::Deserialize)]
            struct HeartbeatResponse {
                traffic_limit: Option<u64>,
                traffic_used: Option<u64>,
            }
            match client.post(&api_url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        print!("\n\r{}", "[!] License has been banned or invalidated by server! Exiting...   ".red());
                        let _ = std::io::stdout().flush();
                        let _ = hb_exit_tx.send(()).await;
                        break;
                    } else if resp.status().is_success() {
                        if let Ok(hb_resp) = resp.json::<HeartbeatResponse>().await {
                            TRAFFIC_LIMIT.store(hb_resp.traffic_limit.unwrap_or(0), Ordering::Relaxed);
                            TRAFFIC_USED.store(hb_resp.traffic_used.unwrap_or(0), Ordering::Relaxed);
                        }
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
    if let Some(ref handle) = bridge_handle {
        handle.abort();
    }
    println!(); // Print newline to move past the carriage-return line

    println!("{}", "[*] Disconnecting and restoring system routing table...".white());
    
    // Explicitly shut down adapter before dropping it
    let _ = adapter.down();

    if let Some((ref srv_ip, ref gw)) = bypass_route_info {
        remove_server_bypass_route(srv_ip, gw, is_debug);
    }

    // Delete temporary firewall rule blocking QUIC (UDP 443)
    let _ = std::process::Command::new("netsh")
        .args(&["advfirewall", "firewall", "delete", "rule", "name=CommercialVPN_BlockQUIC"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

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
     fn configure_tun_interface(interface_name: &str, client_ip: &str, mtu: u32) -> io::Result<()> {
         let mtu_str = mtu.to_string();
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
                 .args(&["link", "set", "dev", interface_name, "mtu", &mtu_str])
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
                 .args(&[interface_name, clean_ip, clean_ip, "netmask", "255.255.255.0", "mtu", &mtu_str, "up"])
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
    is_debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Reset/Initialize traffic counters
    BYTES_SENT.store(0, Ordering::Relaxed);
    BYTES_RECV.store(0, Ordering::Relaxed);
    TRAFFIC_LIMIT.store(config.traffic_limit.unwrap_or(0), Ordering::Relaxed);
    TRAFFIC_USED.store(config.traffic_used.unwrap_or(0), Ordering::Relaxed);

    let server_pubkey_bytes = BASE64.decode(&config.server_pubkey)?;
    let server_pubkey_arr: [u8; 32] = server_pubkey_bytes.try_into()
        .map_err(|_| "Invalid Server Public Key length")?;
    let server_public_key = PublicKey::from(server_pubkey_arr);
    let server_endpoint: SocketAddr = config.endpoint.parse()?;
    let (actual_peer_endpoint, bridge_handle) = setup_tls_proxy_if_needed(&config.tls_endpoint, server_endpoint, is_debug).await?;
    let mtu = if config.tls_endpoint.is_some() { 1360 } else { 1420 };

    #[cfg(target_os = "linux")]
    let interface_name = "tun0";
    #[cfg(target_os = "linux")]
    let tun_file = create_linux_tun(interface_name)?;

    #[cfg(target_os = "macos")]
    let (tun_file, interface_name_str) = create_macos_tun()?;
    #[cfg(target_os = "macos")]
    let interface_name = &interface_name_str;

    configure_tun_interface(interface_name, &config.client_ip, mtu)?;

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

    let domain = match actual_peer_endpoint {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let raw_socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    raw_socket.set_send_buffer_size(2 * 1024 * 1024)?;
    raw_socket.set_recv_buffer_size(2 * 1024 * 1024)?;
    
    let bind_addr = match actual_peer_endpoint {
        SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>()?,
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>()?,
    };
    raw_socket.bind(&bind_addr.into())?;
    let udp_socket: std::net::UdpSocket = raw_socket.into();
    udp_socket.connect(actual_peer_endpoint)?;

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
                    BYTES_SENT.fetch_add(len as u64, Ordering::Relaxed);
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
                            BYTES_RECV.fetch_add(bytes.len() as u64, Ordering::Relaxed);
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
        let mut last_bytes = 0;
        loop {
            let now_ts = chrono::Utc::now().timestamp();
            let diff = expires_at_ts - now_ts;
            if diff > 0 {
                let days = diff / 86400;
                let hours = (diff % 86400) / 3600;
                let minutes = (diff % 3600) / 60;
                let seconds = diff % 60;

                let sent = BYTES_SENT.load(Ordering::Relaxed);
                let recv = BYTES_RECV.load(Ordering::Relaxed);
                let current_bytes = sent + recv;
                let speed_bytes = if current_bytes >= last_bytes { current_bytes - last_bytes } else { 0 };
                last_bytes = current_bytes;

                let limit = TRAFFIC_LIMIT.load(Ordering::Relaxed);
                let used = TRAFFIC_USED.load(Ordering::Relaxed);

                let traffic_str = if limit > 0 {
                    let total_used = used + current_bytes;
                    let remaining_bytes = if limit > total_used { limit - total_used } else { 0 };
                    format!("Traffic Left: {} / {}", format_bytes(remaining_bytes), format_bytes(limit))
                } else {
                    format!("Traffic Used: {}", format_bytes(used + current_bytes))
                };

                let speed_str = format_bytes(speed_bytes);

                print!(
                    "\r{}",
                    format!(
                        "[+] Remaining Time: {}d {}h {}m {}s | {} | Session: {} ({}/s)   ",
                        days, hours, minutes, seconds,
                        traffic_str,
                        format_bytes(current_bytes),
                        speed_str
                    ).green()
                );
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
            let top_10 = crate::monitor::get_top_10_apps();
            let app_traffic_json: Vec<serde_json::Value> = top_10.iter().map(|(app, bytes)| {
                serde_json::json!({
                    "app": app,
                    "bytes": bytes
                })
            }).collect();
            let payload = serde_json::json!({
                "license_key": hb_license_key,
                "device_info": hb_device_info,
                "app_traffic": app_traffic_json
            });
            #[derive(serde::Deserialize)]
            struct HeartbeatResponse {
                traffic_limit: Option<u64>,
                traffic_used: Option<u64>,
            }
            match client.post(&api_url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        print!("\n\r{}", "[!] License has been banned or invalidated by server! Exiting...   ".red());
                        let _ = std::io::stdout().flush();
                        let _ = hb_exit_tx.send(()).await;
                        break;
                    } else if resp.status().is_success() {
                        if let Ok(hb_resp) = resp.json::<HeartbeatResponse>().await {
                            TRAFFIC_LIMIT.store(hb_resp.traffic_limit.unwrap_or(0), Ordering::Relaxed);
                            TRAFFIC_USED.store(hb_resp.traffic_used.unwrap_or(0), Ordering::Relaxed);
                        }
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
    if let Some(ref handle) = bridge_handle {
        handle.abort();
    }
    println!(); // Print newline to move past the carriage-return line

    println!("{}", "[*] Disconnecting...".white());
    println!("{}", "[+] VPN Disconnected.".green());
    Ok(())
}
