import base64
import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Static salt used for key derivation. Must match the client.
STATIC_SALT = b"commercial_vpn_static_salt_value_12345"

def derive_key(license_key: str) -> bytes:
    """
    Derive a 256-bit AES key from the user's license key using PBKDF2.
    Using 10,000 iterations for responsive authentication.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=STATIC_SALT,
        iterations=10000,
    )
    return kdf.derive(license_key.encode("utf-8"))

def encrypt_payload(data: dict, license_key: str) -> dict:
    """
    Encrypts a JSON dictionary payload using AES-256-GCM.
    Returns base64 encoded nonce and ciphertext (which contains the 16-byte auth tag at the end).
    """
    key = derive_key(license_key)
    aesgcm = AESGCM(key)
    
    # Generate a random 12-byte nonce
    nonce = os.urandom(12)
    
    # Serialize dict to JSON string and encode as bytes
    json_bytes = json.dumps(data).encode("utf-8")
    
    # Encrypt (returns ciphertext + 16-byte tag)
    ciphertext_with_tag = aesgcm.encrypt(nonce, json_bytes, None)
    
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("utf-8")
    }
