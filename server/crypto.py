import base64
import json
import os
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding

def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_payload(data: dict, rsa_pubkey_b64: str) -> dict:
    """
    Encrypts a JSON dictionary payload using XOR with a random key,
    and encrypts the XOR key using the client's RSA public key.
    """
    # 1. Generate a random 32-byte XOR key
    xor_key = os.urandom(32)
    
    # 2. Encrypt config using XOR
    payload_bytes = json.dumps(data).encode('utf-8')
    ciphertext_bytes = xor_crypt(payload_bytes, xor_key)
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
    
    # 3. Encrypt XOR key using RSA public key
    rsa_pubkey_bytes = base64.b64decode(rsa_pubkey_b64)
    public_key = load_der_public_key(rsa_pubkey_bytes)
    
    encrypted_xor_key = public_key.encrypt(
        xor_key,
        padding.PKCS1v15()
    )
    nonce_b64 = base64.b64encode(encrypted_xor_key).decode('utf-8')
    
    return {
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64
    }
