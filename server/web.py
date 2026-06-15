import datetime
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from db import SessionLocal, ActivationKey, init_db
from main import remove_wg_peer, cleanup_empty_peers, generate_random_key

app = Flask(__name__)
app.secret_key = "major_vpn_secret_key_secure_and_private"

# Built-in credentials
ADMIN_USER = "admin"
ADMIN_PASS = "aasdff12"

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USER and password == ADMIN_PASS:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

# ==============================================================================
# AJAX API Endpoints for Dashboard
# ==============================================================================

@app.route("/api/keys", methods=["GET"])
@login_required
def api_get_keys():
    db = SessionLocal()
    try:
        keys = db.query(ActivationKey).all()
        result = []
        now = datetime.datetime.utcnow()
        for k in keys:
            # Determine status
            status = "unused"
            if k.is_banned == 1:
                status = "banned"
            elif k.device_info is not None:
                if k.expires_at and now > k.expires_at:
                    status = "expired"
                else:
                    status = "active"
            
            result.append({
                "id": k.id,
                "key": k.key,
                "activation_days": k.activation_days,
                "duration_seconds": k.duration_seconds,
                "device_info": k.device_info,
                "client_pubkey": k.client_pubkey,
                "assigned_ip": k.assigned_ip,
                "activated_at": k.activated_at.strftime("%Y-%m-%d %H:%M:%S") if k.activated_at else None,
                "expires_at": k.expires_at.strftime("%Y-%m-%d %H:%M:%S") if k.expires_at else None,
                "is_banned": k.is_banned,
                "status": status
            })
        return jsonify(result)
    finally:
        db.close()

@app.route("/api/keys", methods=["POST"])
@login_required
def api_create_key():
    data = request.json or {}
    key_str = data.get("key", "").strip()
    duration_type = data.get("duration_type", "days")  # days, hours, minutes, seconds
    duration_val = data.get("duration_val", 30)

    try:
        duration_val = int(duration_val)
    except ValueError:
        return jsonify({"error": "Duration must be an integer."}), 400

    if duration_val <= 0:
        return jsonify({"error": "Duration must be greater than zero."}), 400

    # Calculate duration in seconds
    duration_seconds = None
    activation_days = 30

    if duration_type == "seconds":
        duration_seconds = duration_val
        activation_days = max(1, int(duration_val / 86400))
    elif duration_type == "minutes":
        duration_seconds = duration_val * 60
        activation_days = max(1, int(duration_seconds / 86400))
    elif duration_type == "hours":
        duration_seconds = duration_val * 3600
        activation_days = max(1, int(duration_seconds / 86400))
    else:  # days
        activation_days = duration_val
        duration_seconds = duration_val * 86400

    db = SessionLocal()
    try:
        if key_str:
            existing = db.query(ActivationKey).filter(ActivationKey.key == key_str).first()
            if existing:
                return jsonify({"error": f"Key '{key_str}' already exists."}), 400
        else:
            while True:
                key_str = generate_random_key()
                existing = db.query(ActivationKey).filter(ActivationKey.key == key_str).first()
                if not existing:
                    break
        
        new_key = ActivationKey(
            key=key_str,
            activation_days=activation_days,
            duration_seconds=duration_seconds,
            is_banned=0
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)
        return jsonify({"status": "success", "key": new_key.key})
    finally:
        db.close()

@app.route("/api/keys/<int:key_id>/ban", methods=["POST"])
@login_required
def api_toggle_ban(key_id):
    db = SessionLocal()
    try:
        key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
        if not key_item:
            return jsonify({"error": "Key not found."}), 404
        
        # Toggle ban
        new_ban_state = 0 if key_item.is_banned == 1 else 1
        key_item.is_banned = new_ban_state
        db.commit()
        db.refresh(key_item)

        # Kick client if banned
        if new_ban_state == 1 and key_item.client_pubkey:
            remove_wg_peer(key_item.client_pubkey)
            cleanup_empty_peers()
            print(f"[WEB ADMIN] Key {key_item.key} banned. Connected client {key_item.client_pubkey} kicked.")

        return jsonify({"status": "success", "is_banned": key_item.is_banned})
    finally:
        db.close()

@app.route("/api/keys/<int:key_id>/unbind", methods=["POST"])
@login_required
def api_unbind_device(key_id):
    db = SessionLocal()
    try:
        key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
        if not key_item:
            return jsonify({"error": "Key not found."}), 404
        
        old_pubkey = key_item.client_pubkey

        # Clear active lease properties
        key_item.device_info = None
        key_item.client_pubkey = None
        key_item.assigned_ip = None
        key_item.activated_at = None
        key_item.expires_at = None
        db.commit()

        # Kick client if connected
        if old_pubkey:
            remove_wg_peer(old_pubkey)
            cleanup_empty_peers()
            print(f"[WEB ADMIN] Key {key_item.key} unbound. Client {old_pubkey} kicked.")

        return jsonify({"status": "success"})
    finally:
        db.close()

@app.route("/api/keys/<int:key_id>/delete", methods=["POST"])
@login_required
def api_delete_key(key_id):
    db = SessionLocal()
    try:
        key_item = db.query(ActivationKey).filter(ActivationKey.id == key_id).first()
        if not key_item:
            return jsonify({"error": "Key not found."}), 404
        
        old_pubkey = key_item.client_pubkey

        db.delete(key_item)
        db.commit()

        # Kick client if connected
        if old_pubkey:
            remove_wg_peer(old_pubkey)
            cleanup_empty_peers()
            print(f"[WEB ADMIN] Key deleted. Client {old_pubkey} kicked.")

        return jsonify({"status": "success"})
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    # Listen on port 8080
    app.run(host="0.0.0.0", port=8080, debug=True)
