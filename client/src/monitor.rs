use std::sync::Mutex;
use std::sync::OnceLock;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

static BYPASS_SERVER: OnceLock<Mutex<Option<(Ipv4Addr, u16)>>> = OnceLock::new();

fn get_bypass_server() -> &'static Mutex<Option<(Ipv4Addr, u16)>> {
    BYPASS_SERVER.get_or_init(|| Mutex::new(None))
}

pub fn set_bypass_server(ip_str: &str, port: u16) {
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let mut guard = get_bypass_server().lock().unwrap();
        *guard = Some((ip, port));
    }
}

// Global application traffic map: AppName -> AccumulatedBytes
fn get_app_traffic() -> &'static Mutex<HashMap<String, u64>> {
    static APP_TRAFFIC: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    APP_TRAFFIC.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn get_top_10_apps() -> Vec<(String, u64)> {
    let map = get_app_traffic().lock().unwrap();
    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    entries.truncate(10);
    entries
}

#[cfg(not(target_os = "windows"))]
pub fn start_monitor() {
    // No-op for non-Windows platforms
}

#[cfg(target_os = "windows")]
pub fn start_monitor() {
    std::thread::spawn(|| {
        if let Err(e) = run_monitor_loop() {
            eprintln!("[Monitor Error] Loop terminated: {:?}", e);
        }
    });
}

#[cfg(target_os = "windows")]
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
enum ConnectionKey {
    V4 {
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
    },
    V6 {
        local_addr: [u8; 16],
        local_port: u32,
        remote_addr: [u8; 16],
        remote_port: u32,
    },
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct MIB_TCPROW_OWNER_PID {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
    dw_owning_pid: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MIB_TCPTABLE_OWNER_PID {
    dw_num_entries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct MIB_TCP6ROW_OWNER_PID {
    uc_local_addr: [u8; 16],
    dw_local_scope_id: u32,
    dw_local_port: u32,
    uc_remote_addr: [u8; 16],
    dw_remote_scope_id: u32,
    dw_remote_port: u32,
    dw_state: u32,
    dw_owning_pid: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct MIB_TCP6TABLE_OWNER_PID {
    dw_num_entries: u32,
    table: [MIB_TCP6ROW_OWNER_PID; 1],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct MIB_TCPROW {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct MIB_TCP6ROW {
    state: u32,
    local_addr: [u8; 16],
    dw_local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    dw_remote_scope_id: u32,
    remote_port: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct TCP_ESTATS_DATA_RW_v0 {
    enable_collection: u8,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct TCP_ESTATS_DATA_ROD_v0 {
    data_bytes_out: u64,
    data_segs_out: u64,
    data_bytes_in: u64,
    data_segs_in: u64,
    segs_out: u64,
    segs_in: u64,
    soft_errors: u32,
    soft_error_reason: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_max: u32,
    padding1: u32,
    thru_bytes_acked: u64,
    rcv_nxt: u32,
    padding2: u32,
    thru_bytes_received: u64,
}

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn SetPerTcpConnectionEStats(
        Row: *const u8,
        EstatsType: i32,
        Rw: *const u8,
        RwVersion: u32,
        RwSize: u32,
        RwOffset: u32,
    ) -> u32;

    fn GetPerTcpConnectionEStats(
        Row: *const u8,
        EstatsType: i32,
        Rw: *mut u8,
        RwVersion: u32,
        RwSize: u32,
        Ros: *mut u8,
        RosVersion: u32,
        RosSize: u32,
        Rod: *mut u8,
        RodVersion: u32,
        RodSize: u32,
    ) -> u32;

    fn SetPerTcp6ConnectionEStats(
        Row: *const u8,
        EstatsType: i32,
        Rw: *const u8,
        RwVersion: u32,
        RwSize: u32,
        RwOffset: u32,
    ) -> u32;

    fn GetPerTcp6ConnectionEStats(
        Row: *const u8,
        EstatsType: i32,
        Rw: *mut u8,
        RwVersion: u32,
        RwSize: u32,
        Ros: *mut u8,
        RosVersion: u32,
        RosSize: u32,
        Rod: *mut u8,
        RodVersion: u32,
        RodSize: u32,
    ) -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(
        hProcess: *mut std::ffi::c_void,
        dwFlags: u32,
        lpExeName: *mut u16,
        lpdwSize: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn get_process_name(pid: u32) -> String {
    if pid == 0 {
        return "Idle".to_string();
    }
    if pid == 4 {
        return "System".to_string();
    }
    unsafe {
        let handle = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if handle.is_null() {
            return format!("PID_{}", pid);
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let ret = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ret != 0 {
            let os_str = std::ffi::OsString::from_wide(&buffer[..size as usize]);
            if let Some(path_str) = os_str.to_str() {
                if let Some(name) = std::path::Path::new(path_str).file_name() {
                    return name.to_string_lossy().into_owned();
                }
            }
        }
        format!("PID_{}", pid)
    }
}

#[cfg(target_os = "windows")]
fn query_ipv4_table() -> Vec<MIB_TCPROW_OWNER_PID> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            1, // bOrder = true
            2, // AF_INET
            5, // TCP_TABLE_OWNER_PID_ALL
            0,
        );
    }
    if size == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr(),
            &mut size,
            1,
            2,
            5,
            0,
        )
    };
    if ret != 0 {
        return Vec::new();
    }
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let num_entries = table.dw_num_entries as usize;
    let mut entries = Vec::with_capacity(num_entries);
    unsafe {
        let ptr = buffer.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..num_entries {
            entries.push(*ptr.add(i));
        }
    }
    entries
}

#[cfg(target_os = "windows")]
fn query_ipv6_table() -> Vec<MIB_TCP6ROW_OWNER_PID> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            1, // bOrder = true
            23, // AF_INET6
            5, // TCP_TABLE_OWNER_PID_ALL
            0,
        );
    }
    if size == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr(),
            &mut size,
            1,
            23,
            5,
            0,
        )
    };
    if ret != 0 {
        return Vec::new();
    }
    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let num_entries = table.dw_num_entries as usize;
    let mut entries = Vec::with_capacity(num_entries);
    unsafe {
        let ptr = buffer.as_ptr().add(4) as *const MIB_TCP6ROW_OWNER_PID;
        for i in 0..num_entries {
            entries.push(*ptr.add(i));
        }
    }
    entries
}

#[cfg(target_os = "windows")]
fn run_monitor_loop() -> Result<(), Box<dyn std::error::Error>> {
    let mut tracked_connections: HashMap<ConnectionKey, (u64, u64, u32, String)> = HashMap::new();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));

        let ipv4_entries = query_ipv4_table();
        let ipv6_entries = query_ipv6_table();

        let bypass = {
            let guard = get_bypass_server().lock().unwrap();
            *guard
        };
        let mut current_keys = HashSet::new();

        // 1. Process IPv4 Connections
        for row in ipv4_entries {
            if row.dw_state != 5 { // Only ESTABLISHED
                continue;
            }
            if let Some((bypass_ip, bypass_port)) = bypass {
                let remote_ip = Ipv4Addr::from(row.dw_remote_addr.to_ne_bytes());
                let remote_port = u16::from_be(row.dw_remote_port as u16);
                if remote_ip == bypass_ip && remote_port == bypass_port {
                    continue;
                }
            }
            let key = ConnectionKey::V4 {
                local_addr: row.dw_local_addr,
                local_port: row.dw_local_port,
                remote_addr: row.dw_remote_addr,
                remote_port: row.dw_remote_port,
            };
            current_keys.insert(key.clone());

            let entry = tracked_connections.entry(key.clone());
            match entry {
                std::collections::hash_map::Entry::Vacant(v) => {
                    // Enable statistics
                    let mib_row = MIB_TCPROW {
                        dw_state: row.dw_state,
                        dw_local_addr: row.dw_local_addr,
                        dw_local_port: row.dw_local_port,
                        dw_remote_addr: row.dw_remote_addr,
                        dw_remote_port: row.dw_remote_port,
                    };
                    let rw = TCP_ESTATS_DATA_RW_v0 { enable_collection: 1 };
                    let set_ret = unsafe {
                        SetPerTcpConnectionEStats(
                            &mib_row as *const MIB_TCPROW as *const u8,
                            1, // TcpConnectionEstatsData
                            &rw as *const TCP_ESTATS_DATA_RW_v0 as *const u8,
                            0,
                            std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32,
                            0,
                        )
                    };
                    if set_ret == 0 {
                        let proc_name = get_process_name(row.dw_owning_pid);
                        v.insert((0, 0, row.dw_owning_pid, proc_name));
                    }
                }
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let (last_in, last_out, _pid, proc_name) = o.get_mut();
                    let mib_row = MIB_TCPROW {
                        dw_state: row.dw_state,
                        dw_local_addr: row.dw_local_addr,
                        dw_local_port: row.dw_local_port,
                        dw_remote_addr: row.dw_remote_addr,
                        dw_remote_port: row.dw_remote_port,
                    };
                    let mut rod = unsafe { std::mem::zeroed::<TCP_ESTATS_DATA_ROD_v0>() };
                    let get_ret = unsafe {
                        GetPerTcpConnectionEStats(
                            &mib_row as *const MIB_TCPROW as *const u8,
                            1, // TcpConnectionEstatsData
                            std::ptr::null_mut(),
                            0,
                            0,
                            std::ptr::null_mut(),
                            0,
                            0,
                            &mut rod as *mut TCP_ESTATS_DATA_ROD_v0 as *mut u8,
                            0,
                            96, // Fixed struct size verified by prober
                        )
                    };
                    if get_ret == 0 {
                        let delta_in = rod.data_bytes_in.saturating_sub(*last_in);
                        let delta_out = rod.data_bytes_out.saturating_sub(*last_out);
                        if delta_in > 0 || delta_out > 0 {
                            let total_delta = delta_in + delta_out;
                            let mut map = get_app_traffic().lock().unwrap();
                            let acc = map.entry(proc_name.clone()).or_insert(0);
                            *acc += total_delta;

                            *last_in = rod.data_bytes_in;
                            *last_out = rod.data_bytes_out;
                        }
                    }
                }
            }
        }

        // 2. Process IPv6 Connections
        for row in ipv6_entries {
            if row.dw_state != 5 { // Only ESTABLISHED
                continue;
            }
            let key = ConnectionKey::V6 {
                local_addr: row.uc_local_addr,
                local_port: row.dw_local_port,
                remote_addr: row.uc_remote_addr,
                remote_port: row.dw_remote_port,
            };
            current_keys.insert(key.clone());

            let entry = tracked_connections.entry(key.clone());
            match entry {
                std::collections::hash_map::Entry::Vacant(v) => {
                    // Enable statistics
                    let mib_row = MIB_TCP6ROW {
                        state: row.dw_state,
                        local_addr: row.uc_local_addr,
                        dw_local_scope_id: row.dw_local_scope_id,
                        local_port: row.dw_local_port,
                        remote_addr: row.uc_remote_addr,
                        dw_remote_scope_id: row.dw_remote_scope_id,
                        remote_port: row.dw_remote_port,
                    };
                    let rw = TCP_ESTATS_DATA_RW_v0 { enable_collection: 1 };
                    let set_ret = unsafe {
                        SetPerTcp6ConnectionEStats(
                            &mib_row as *const MIB_TCP6ROW as *const u8,
                            1, // TcpConnectionEstatsData
                            &rw as *const TCP_ESTATS_DATA_RW_v0 as *const u8,
                            0,
                            std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32,
                            0,
                        )
                    };
                    if set_ret == 0 {
                        let proc_name = get_process_name(row.dw_owning_pid);
                        v.insert((0, 0, row.dw_owning_pid, proc_name));
                    }
                }
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let (last_in, last_out, _pid, proc_name) = o.get_mut();
                    let mib_row = MIB_TCP6ROW {
                        state: row.dw_state,
                        local_addr: row.uc_local_addr,
                        dw_local_scope_id: row.dw_local_scope_id,
                        local_port: row.dw_local_port,
                        remote_addr: row.uc_remote_addr,
                        dw_remote_scope_id: row.dw_remote_scope_id,
                        remote_port: row.dw_remote_port,
                    };
                    let mut rod = unsafe { std::mem::zeroed::<TCP_ESTATS_DATA_ROD_v0>() };
                    let get_ret = unsafe {
                        GetPerTcp6ConnectionEStats(
                            &mib_row as *const MIB_TCP6ROW as *const u8,
                            1, // TcpConnectionEstatsData
                            std::ptr::null_mut(),
                            0,
                            0,
                            std::ptr::null_mut(),
                            0,
                            0,
                            &mut rod as *mut TCP_ESTATS_DATA_ROD_v0 as *mut u8,
                            0,
                            96, // Fixed struct size verified by prober
                        )
                    };
                    if get_ret == 0 {
                        let delta_in = rod.data_bytes_in.saturating_sub(*last_in);
                        let delta_out = rod.data_bytes_out.saturating_sub(*last_out);
                        if delta_in > 0 || delta_out > 0 {
                            let total_delta = delta_in + delta_out;
                            let mut map = get_app_traffic().lock().unwrap();
                            let acc = map.entry(proc_name.clone()).or_insert(0);
                            *acc += total_delta;

                            *last_in = rod.data_bytes_in;
                            *last_out = rod.data_bytes_out;
                        }
                    }
                }
            }
        }

        // 3. Cleanup closed connections
        tracked_connections.retain(|k, _| current_keys.contains(k));
    }
}
