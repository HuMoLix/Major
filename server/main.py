import datetime
import os
import random
import string
import asyncio
import time
import hashlib
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import get_db, ActivationKey, init_db, SessionLocal
from crypto import encrypt_payload

# Initialize FastAPI
app = FastAPI(title="Commercial VPN Activation Server", version="1.5.11")

# Generate a random administrator password on startup
import secrets
_alphabet = string.ascii_letters + string.digits
ADMIN_PASS = "".join(secrets.choice(_alphabet) for _mut in range(12))
try:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
    _pass_file = os.path.join(_base_dir, "admin_password.txt")
    with open(_pass_file, "w") as _f:
        _f.write(ADMIN_PASS)
except Exception as _e:
    print(f"[ADMIN ERROR] Failed to save admin password: {_e}")

print(f"==================================================")
print(f"[ADMIN] Generated random admin password: {ADMIN_PASS}")
print(f"[ADMIN] You can use this to log into the web dashboard.")
print(f"==================================================")

PEER_SESSIONS = {}  # {pubkey: last_seen_bytes}

def get_wg_transfers() -> dict:
    """Runs wg show wg0 dump and parses it. Returns {pubkey: (rx_bytes, tx_bytes)}"""
    transfers = {}
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) >= 8:
                    pubkey = parts[0]
                    rx_bytes = int(parts[5])
                    tx_bytes = int(parts[6])
                    transfers[pubkey] = (rx_bytes, tx_bytes)
    except Exception as e:
        print(f"[WG STATS ERROR] Failed to query wireguard transfers: {e}")
    return transfers

async def auto_cleanup_expired_keys_loop():
    """
    Background task that periodically scans the database for expired or traffic-exceeded activation keys
    that are currently connected (have client_pubkey), removes their WireGuard peers/tc rules,
    and clears their active lease in the DB.
    """
    global PEER_SESSIONS
    last_debug_code = None
    while True:
        try:
            # Print debug code when it changes
            current_minute = int(time.time() // 60)
            current_code = generate_debug_code(current_minute)
            if current_code != last_debug_code:
                print(f"[DEBUG CODE] Current debug validation code: {current_code}")
                last_debug_code = current_code
        except Exception as e:
            print(f"[DEBUG CODE ERROR] {e}")
        try:
            db = SessionLocal()
            try:
                now = datetime.datetime.utcnow()
                transfers = get_wg_transfers()
                active_keys = db.query(ActivationKey).filter(ActivationKey.client_pubkey.isnot(None)).all()

                for key_item in active_keys:
                    pubkey = key_item.client_pubkey
                    
                    # 1. Update traffic usage
                    if pubkey in transfers:
                        rx, tx = transfers[pubkey]
                        total = rx + tx
                        last_seen = PEER_SESSIONS.get(pubkey, 0)
                        increment = total - last_seen
                        if increment > 0:
                            key_item.traffic_used = (key_item.traffic_used or 0) + increment
                            db.commit()
                            PEER_SESSIONS[pubkey] = total
                    else:
                        PEER_SESSIONS.pop(pubkey, None)

                    # 2. Check expiration & traffic limit
                    is_expired = key_item.expires_at is not None and key_item.expires_at < now
                    is_over_limit = key_item.traffic_limit is not None and (key_item.traffic_used or 0) >= key_item.traffic_limit

                    if is_expired or is_over_limit:
                        reason = "expired" if is_expired else "traffic limit exceeded"
                        print(f"[AUTO DISCONNECT] Key {key_item.key} is being disconnected. Reason: {reason}")
                        
                        remove_wg_peer(pubkey, key_item.assigned_ip)
                        key_item.client_pubkey = None
                        key_item.assigned_ip = None
                        db.commit()
                        PEER_SESSIONS.pop(pubkey, None)

                # Clean up any orphan keys in PEER_SESSIONS
                active_pubkeys = {k.client_pubkey for k in active_keys if k.client_pubkey}
                for pk in list(PEER_SESSIONS.keys()):
                    if pk not in active_pubkeys:
                        PEER_SESSIONS.pop(pk, None)

                cleanup_empty_peers()
            finally:
                db.close()
        except Exception as e:
            print(f"[AUTO EXPIRE ERROR] {e}")
        
        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    init_db()
    asyncio.create_task(auto_cleanup_expired_keys_loop())

def load_wg_config():
    """
    Parses /etc/wireguard/wg0.conf to retrieve the PrivateKey and ListenPort,
    derives the PublicKey from the PrivateKey, and returns (public_key, listen_port).
    If the file cannot be read, returns fallback default values.
    """
    fallback_pubkey = "+qRSnn9GcEOELTL2CQPwf1Y9GMYUjBHQ7kqcfW/hl3o="
    fallback_port = 51820
    
    config_path = "/etc/wireguard/wg0.conf"
    if not os.path.exists(config_path):
        return fallback_pubkey, fallback_port
        
    try:
        private_key = None
        listen_port = fallback_port
        
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip().lower()
                    val = val.split("#")[0].strip() # strip comments
                    if key == "privatekey":
                        private_key = val
                    elif key == "listenport":
                        try:
                            listen_port = int(val)
                        except ValueError:
                            pass
                            
        if private_key:
            import subprocess
            proc = subprocess.run(
                ["wg", "pubkey"],
                input=private_key.encode(),
                capture_output=True,
                check=True
            )
            derived_pubkey = proc.stdout.decode().strip()
            return derived_pubkey, listen_port
            
    except Exception as e:
        print(f"[WG CONFIG LOAD WARNING] Failed to parse {config_path}: {e}")
        
    return fallback_pubkey, fallback_port

# Load WireGuard Server Configuration dynamically from /etc/wireguard/wg0.conf
_derived_pubkey, _derived_port = load_wg_config()

# WireGuard Server Configuration Constants (Mocked for local test)
SERVER_WG_PUBLIC_KEY = _derived_pubkey
SERVER_ENDPOINT = f"192.168.52.129:{_derived_port}"  # Localhost endpoint
SERVER_TLS_PORT = 8443
from version import LATEST_CLIENT_VERSION

def generate_debug_code(minute_interval: int) -> str:
    salt = "major_debug_salt_secure_2026"
    data = f"{salt}_{minute_interval}"
    hasher = hashlib.sha256(data.encode('utf-8'))
    digest = hasher.hexdigest().upper()
    return digest[:6]

def verify_debug_code(code: str) -> bool:
    if not code:
        return False
    current_minute = int(time.time() // 60)
    code_cleaned = code.strip().upper()
    if code_cleaned == generate_debug_code(current_minute):
        return True
    if code_cleaned == generate_debug_code(current_minute - 1):
        return True
    return False

class VerifyDebugRequest(BaseModel):
    code: str

class ActivationRequest(BaseModel):
    license_key: str
    client_pubkey: str
    rsa_pubkey: str  # Client RSA public key in DER base64
    device_info: str  # SHA256 hardware fingerprint of client

class AppTrafficItem(BaseModel):
    app: str
    bytes: int

class HeartbeatRequest(BaseModel):
    license_key: str
    device_info: str
    app_traffic: Optional[List[AppTrafficItem]] = None

class AdminKeyCreate(BaseModel):
    key: Optional[str] = None
    activation_days: Optional[int] = 30
    duration_seconds: Optional[int] = None
    is_banned: Optional[int] = 0
    traffic_limit: Optional[int] = None # in bytes
    speed_limit: Optional[int] = None # in Mbps

class AdminKeyUpdate(BaseModel):
    is_banned: Optional[int] = None
    activation_days: Optional[int] = None
    duration_seconds: Optional[int] = None
    device_info: Optional[str] = None
    client_pubkey: Optional[str] = None
    assigned_ip: Optional[str] = None
    expires_at: Optional[datetime.datetime] = None
    traffic_limit: Optional[int] = None
    traffic_used: Optional[int] = None
    speed_limit: Optional[int] = None
    app_traffic_json: Optional[str] = None

class AdminKeyResponse(BaseModel):
    id: int
    key: str
    activation_days: int
    duration_seconds: Optional[int] = None
    device_info: Optional[str] = None
    client_pubkey: Optional[str] = None
    assigned_ip: Optional[str] = None
    activated_at: Optional[datetime.datetime] = None
    expires_at: Optional[datetime.datetime] = None
    is_banned: int
    traffic_limit: Optional[int] = None
    traffic_used: int
    speed_limit: Optional[int] = None
    app_traffic_json: Optional[str] = None

    class Config:
        from_attributes = True

import subprocess

def get_class_id_from_ip(ip: str) -> Optional[int]:
    try:
        clean_ip = ip.split("/")[0]
        parts = clean_ip.split(".")
        return int(parts[-1])
    except Exception:
        return None

def register_wg_peer(pubkey: str, ip: str, speed_limit: Optional[int] = None):
    """
    Registers the peer with the WireGuard network interface and applies speed limits.
    """
    try:
        clean_ip = ip.split("/")[0]
        subprocess.run(
            ["wg", "set", "wg0", "peer", pubkey, "allowed-ips", f"{clean_ip}/32"],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[WG] Successfully registered peer {pubkey} with IP {clean_ip} on interface wg0")

        if speed_limit:
            class_id = get_class_id_from_ip(clean_ip)
            if class_id:
                print(f"[TC] Applying speed limit of {speed_limit}Mbps for peer {pubkey} (IP: {clean_ip}, classid 1:{class_id})...")
                subprocess.run(["tc", "qdisc", "add", "dev", "wg0", "root", "handle", "1:", "htb", "default", "10"], stderr=subprocess.DEVNULL)
                subprocess.run(["tc", "filter", "del", "dev", "wg0", "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", clean_ip], stderr=subprocess.DEVNULL)
                subprocess.run(["tc", "class", "del", "dev", "wg0", "classid", f"1:{class_id}"], stderr=subprocess.DEVNULL)
                subprocess.run(["tc", "class", "add", "dev", "wg0", "parent", "1:", "classid", f"1:{class_id}", "htb", "rate", f"{speed_limit}mbit", "ceil", f"{speed_limit}mbit"], check=True)
                subprocess.run(["tc", "filter", "add", "dev", "wg0", "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", clean_ip, "flowid", f"1:{class_id}"], check=True)
                print(f"[TC] Successfully set speed limit {speed_limit}Mbps for {clean_ip}")
    except subprocess.CalledProcessError as e:
        print(f"[WG/TC ERROR] Command '{e.cmd}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"[WG/TC ERROR] Failed to register peer or apply tc: {str(e)}")

def remove_wg_peer(pubkey: str, ip: Optional[str] = None):
    """
    Removes the peer from the WireGuard interface and cleans up its tc speed limit rules.
    """
    try:
        subprocess.run(
            ["wg", "set", "wg0", "peer", pubkey, "remove"],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[WG] Successfully removed old peer: {pubkey}")
    except subprocess.CalledProcessError as e:
        print(f"[WG ERROR] Command '{e.cmd}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"[WG ERROR] Failed to remove old peer: {str(e)}")

    if ip:
        try:
            clean_ip = ip.split("/")[0]
            class_id = get_class_id_from_ip(clean_ip)
            if class_id:
                subprocess.run(["tc", "filter", "del", "dev", "wg0", "protocol", "ip", "parent", "1:0", "prio", "1", "u32", "match", "ip", "dst", clean_ip], stderr=subprocess.DEVNULL)
                subprocess.run(["tc", "class", "del", "dev", "wg0", "classid", f"1:{class_id}"], stderr=subprocess.DEVNULL)
                print(f"[TC] Successfully cleaned up speed limit rules for {clean_ip}")
        except Exception as e:
            print(f"[TC ERROR] Failed to clean up tc rules: {str(e)}")

def cleanup_empty_peers():
    """
    Scans the WireGuard interface for empty peers (allowed IPs is '(none)')
    and removes them to keep the kernel interface clean.
    """
    try:
        # 运行 wg show wg0 dump 并捕获输出
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) <= 1:
            return  # 没有 Peer (第一行是接口基础元数据)

        # 遍历所有 peer 条目 (跳过第一行网卡元数据)
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 8:
                pubkey = parts[0]
                allowed_ips = parts[3]
                # 如果 Peer 没有任何绑定的 IP 路由，即为失效的空连接，执行移除
                if allowed_ips == "(none)" or not allowed_ips or allowed_ips.strip() == "-":
                    print(f"[WG CLEANUP] Removing empty peer with no allowed IPs: {pubkey}")
                    subprocess.run(
                        ["wg", "set", "wg0", "peer", pubkey, "remove"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
    except subprocess.CalledProcessError as e:
        print(f"[WG CLEANUP ERROR] Command '{e.cmd}' failed with exit code {e.returncode}. Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"[WG CLEANUP ERROR] Failed to clean up empty peers: {str(e)}")

def allocate_ip(db: Session) -> str:
    """
    Finds a free IP in the subnet 10.0.0.2 to 10.0.0.254.
    """
    active_keys = db.query(ActivationKey).filter(ActivationKey.assigned_ip.isnot(None)).all()
    assigned_ips = {k.assigned_ip for k in active_keys}
    
    for i in range(2, 255):
        ip = f"10.0.0.{i}"
        if ip not in assigned_ips:
            return ip
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="IP address pool is exhausted."
    )

@app.post("/api/v1/activate")
def activate(request: ActivationRequest, db: Session = Depends(get_db)):
    # 1. Look up the license key
    license_item = db.query(ActivationKey).filter(ActivationKey.key == request.license_key).first()
    if not license_item:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid activation key."
        )

    # 1.5 Check if banned
    if license_item.is_banned == 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This activation key is banned."
        )

    # 1.6 Check if traffic limit is exceeded
    if license_item.traffic_limit is not None and (license_item.traffic_used or 0) >= license_item.traffic_limit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Traffic limit exceeded."
        )

    now = datetime.datetime.utcnow()

    # 2. Check if the key is already activated/bound
    if license_item.device_info is None:
        # First activation: Bind the device and assign IP
        license_item.device_info = request.device_info
        license_item.client_pubkey = request.client_pubkey
        license_item.assigned_ip = allocate_ip(db)
        license_item.activated_at = now
        if license_item.duration_seconds is not None:
            license_item.expires_at = now + datetime.timedelta(seconds=license_item.duration_seconds)
        else:
            license_item.expires_at = now + datetime.timedelta(days=license_item.activation_days)
        db.commit()
        db.refresh(license_item)
        print(f"[SERVER] Key {license_item.key} activated for first time on device {request.device_info}")
    else:
        # Subsequent activation: Check if hardware fingerprint matches
        if license_item.device_info != request.device_info:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This activation key is already bound to another device."
            )
        
        # Check if expired
        if license_item.expires_at and now > license_item.expires_at:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This activation key has expired."
            )
            
        # Re-allocate IP if it was cleared/disconnected due to previous expiration or traffic limit exceedance
        if license_item.assigned_ip is None:
            license_item.assigned_ip = allocate_ip(db)

        # Update public key in case client re-generated keys
        old_pubkey = license_item.client_pubkey
        if old_pubkey and old_pubkey != request.client_pubkey:
            remove_wg_peer(old_pubkey, license_item.assigned_ip)

        license_item.client_pubkey = request.client_pubkey
        db.commit()
        db.refresh(license_item)
        print(f"[SERVER] Key {license_item.key} verified and re-registered for device {request.device_info}")

    # 3. Synchronize with WireGuard interface
    register_wg_peer(license_item.client_pubkey, license_item.assigned_ip, license_item.speed_limit)

    # 3.5 自动检测并删除内核中无用的空连接 (allowed ips == none)
    cleanup_empty_peers()

    # 4. Prepare the configuration payload
    server_ip = SERVER_ENDPOINT.split(":")[0]
    config_payload = {
        "server_pubkey": SERVER_WG_PUBLIC_KEY,
        "endpoint": SERVER_ENDPOINT,
        "client_ip": f"{license_item.assigned_ip}/32",
        "dns": ["223.5.5.5", "119.29.29.29"],
        "expires_at": int(license_item.expires_at.replace(tzinfo=datetime.timezone.utc).timestamp()) if license_item.expires_at else 0,
        "tls_endpoint": f"{server_ip}:{SERVER_TLS_PORT}",
        "traffic_limit": license_item.traffic_limit,
        "traffic_used": license_item.traffic_used or 0
    }

    # 5. Encrypt payload using the client's RSA public key (XOR + RSA hybrid encryption)
    try:
        encrypted_result = encrypt_payload(config_payload, request.rsa_pubkey)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption error: {str(e)}"
        )

    return {
        "status": "success",
        "nonce": encrypted_result["nonce"],
        "ciphertext": encrypted_result["ciphertext"]
    }

@app.get("/api/v1/status")
def server_status():
    return {"status": "online", "message": "VPN API activation server is ready."}

@app.post("/api/v1/verify-debug")
def verify_debug(request: VerifyDebugRequest):
    if verify_debug_code(request.code):
        return {"status": "success", "message": "Verification successful."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid debug validation code."
        )

@app.get("/api/v1/version")
def get_latest_version():
    return {"latest_version": LATEST_CLIENT_VERSION}

@app.post("/api/v1/heartbeat")
def heartbeat(request: HeartbeatRequest, db: Session = Depends(get_db)):
    key_item = db.query(ActivationKey).filter(ActivationKey.key == request.license_key).first()
    if not key_item:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid activation key."
        )
    
    if key_item.is_banned == 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This activation key is banned."
        )
        
    if key_item.device_info != request.device_info:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hardware fingerprint mismatch."
        )
        
    now = datetime.datetime.utcnow()
    if key_item.expires_at and now > key_item.expires_at:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This activation key has expired."
        )
    
    if key_item.traffic_limit is not None and key_item.traffic_used >= key_item.traffic_limit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Traffic limit exceeded."
        )

    if request.app_traffic is not None:
        import json
        app_list = [{"app": item.app, "bytes": item.bytes} for item in request.app_traffic]
        key_item.app_traffic_json = json.dumps(app_list)
        db.commit()
        
    return {
        "status": "ok",
        "message": "Heartbeat active.",
        "traffic_limit": key_item.traffic_limit,
        "traffic_used": key_item.traffic_used or 0
    }


# ==============================================================================
# Admin CRUD Endpoints
# ==============================================================================

def generate_random_key() -> str:
    """Generates a readable key like KEY-ABCD-EFGH-IJKL-MNOP"""
    segments = []
    for _ in range(4):
        seg = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
        segments.append(seg)
    return "KEY-" + "-".join(segments)

@app.get("/api/v1/admin/keys", response_model=List[AdminKeyResponse])
def admin_get_all_keys(db: Session = Depends(get_db)):
    return db.query(ActivationKey).all()

@app.get("/api/v1/admin/keys/{key_id}", response_model=AdminKeyResponse)
def admin_get_key(key_id: int, db: Session = Depends(get_db)):
    key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
    if not key_item:
        raise HTTPException(status_code=404, detail="Key not found.")
    return key_item

@app.post("/api/v1/admin/keys", response_model=AdminKeyResponse, status_code=status.HTTP_201_CREATED)
def admin_create_key(payload: AdminKeyCreate, db: Session = Depends(get_db)):
    key_str = payload.key
    if key_str:
        existing = db.query(ActivationKey).filter(ActivationKey.key == key_str).first()
        if existing:
            raise HTTPException(status_code=400, detail="Key already exists.")
    else:
        while True:
            key_str = generate_random_key()
            existing = db.query(ActivationKey).filter(ActivationKey.key == key_str).first()
            if not existing:
                break
    
    days = payload.activation_days
    if days is None:
        if payload.duration_seconds is not None:
            days = max(1, int(payload.duration_seconds / 86400))
        else:
            days = 30

    new_key = ActivationKey(
        key=key_str,
        activation_days=days,
        duration_seconds=payload.duration_seconds,
        is_banned=payload.is_banned or 0,
        traffic_limit=payload.traffic_limit,
        speed_limit=payload.speed_limit
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    return new_key

@app.put("/api/v1/admin/keys/{key_id}", response_model=AdminKeyResponse)
def admin_update_key(key_id: int, payload: AdminKeyUpdate, db: Session = Depends(get_db)):
    key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
    if not key_item:
        raise HTTPException(status_code=404, detail="Key not found.")
    
    update_data = payload.model_dump(exclude_unset=True)
    
    going_to_ban = False
    if "is_banned" in update_data and update_data["is_banned"] == 1 and key_item.is_banned != 1:
        going_to_ban = True

    old_pubkey = key_item.client_pubkey
    old_ip = key_item.assigned_ip
    old_speed_limit = key_item.speed_limit

    for field, value in update_data.items():
        setattr(key_item, field, value)

    db.commit()
    db.refresh(key_item)

    # Disconnect client immediately if banned
    if (going_to_ban or (key_item.is_banned == 1)) and old_pubkey:
        remove_wg_peer(old_pubkey, old_ip)
        cleanup_empty_peers()
    elif old_pubkey and old_ip and "speed_limit" in update_data and update_data["speed_limit"] != old_speed_limit:
        register_wg_peer(old_pubkey, old_ip, key_item.speed_limit)

    return key_item

@app.delete("/api/v1/admin/keys/{key_id}")
def admin_delete_key(key_id: int, db: Session = Depends(get_db)):
    key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
    if not key_item:
        raise HTTPException(status_code=404, detail="Key not found.")
    
    # If the key has an active peer connection, remove it first
    if key_item.client_pubkey:
        remove_wg_peer(key_item.client_pubkey, key_item.assigned_ip)
        cleanup_empty_peers()

    db.delete(key_item)
    db.commit()
    return {"status": "success", "message": f"Activation key with ID {key_id} has been deleted."}
