import datetime
from main import (
    admin_create_key,
    admin_get_all_keys,
    admin_get_key,
    admin_update_key,
    admin_delete_key,
    activate,
    AdminKeyCreate,
    AdminKeyUpdate,
    ActivationRequest,
    heartbeat,
    HeartbeatRequest
)
from db import SessionLocal, ActivationKey

def test_admin_flow():
    # 1. Clear database activation_keys for testing
    db = SessionLocal()
    try:
        db.query(ActivationKey).delete()
        db.commit()
    finally:
        db.close()

    db = SessionLocal()
    try:
        print("\n--- 1. Testing Admin Key Creation ---")
        # 1.1 Create key with default activation_days (30 days)
        payload = AdminKeyCreate()
        key_30d = admin_create_key(payload=payload, db=db)
        print(f"Created default key: {key_30d.key}, days={key_30d.activation_days}, duration_seconds={key_30d.duration_seconds}")
        assert key_30d.activation_days == 30
        assert key_30d.duration_seconds is None

        # 1.2 Create key with custom duration (e.g., 3600 seconds / 1 hour)
        payload = AdminKeyCreate(duration_seconds=3600)
        key_custom = admin_create_key(payload=payload, db=db)
        print(f"Created custom key: {key_custom.key}, days={key_custom.activation_days}, duration_seconds={key_custom.duration_seconds}")
        assert key_custom.duration_seconds == 3600

        # 1.3 Create key with custom key name and specific days
        custom_key_str = "KEY-MY-SUPER-TEST-KEY"
        payload = AdminKeyCreate(key=custom_key_str, activation_days=10)
        key_spec = admin_create_key(payload=payload, db=db)
        print(f"Created specified key: {key_spec.key}, days={key_spec.activation_days}")
        assert key_spec.key == custom_key_str
        assert key_spec.activation_days == 10

        print("\n--- 2. Testing Retrieve Keys ---")
        # 2.1 Get all keys
        keys_list = admin_get_all_keys(db=db)
        print(f"Retrieved {len(keys_list)} keys from DB.")
        assert len(keys_list) == 3

        # 2.2 Get single key by ID
        key_id = key_custom.id
        retrieved_key = admin_get_key(key_id=key_id, db=db)
        assert retrieved_key.key == key_custom.key
        print(f"Successfully retrieved key by ID {key_id}.")

        print("\n--- 3. Testing Key Activation and Custom Duration ---")
        # Generate test RSA keypair
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric import padding
        import base64
        import json
        from crypto import xor_crypt

        test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        test_public_key = test_private_key.public_key()
        der_bytes = test_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        rsa_pubkey_b64 = base64.b64encode(der_bytes).decode('utf-8')

        # 3.1 Activate the custom key (3600 seconds)
        client_pubkey = "35667cda01d0b4aa4fe9e3d1164cf2fd7af0c72b8243ccd275781cfe502ed9b4"
        device_info = "TEST-DEVICE-HARDWARE-ID"
        req = ActivationRequest(
            license_key=key_custom.key,
            client_pubkey=client_pubkey,
            rsa_pubkey=rsa_pubkey_b64,
            device_info=device_info
        )
        # Call activate function
        resp = activate(request=req, db=db)
        print("Activation successful for custom 1-hour key.")

        # Verify decryption works
        encrypted_xor_key = base64.b64decode(resp["nonce"])
        ciphertext_bytes = base64.b64decode(resp["ciphertext"])
        decrypted_xor_key = test_private_key.decrypt(
            encrypted_xor_key,
            padding.PKCS1v15()
        )
        decrypted_payload_bytes = xor_crypt(ciphertext_bytes, decrypted_xor_key)
        decrypted_config = json.loads(decrypted_payload_bytes.decode('utf-8'))
        print(f"Successfully decrypted config in test: {decrypted_config}")
        assert decrypted_config["server_pubkey"] == "+qRSnn9GcEOELTL2CQPwf1Y9GMYUjBHQ7kqcfW/hl3o="

        # 3.2 Verify expiration date in DB is 1 hour (3600s) from activation time
        # Refresh the key from DB
        db.refresh(key_custom)
        time_diff = (key_custom.expires_at - key_custom.activated_at).total_seconds()
        print(f"Activation diff: {time_diff} seconds (Expected: 3600)")
        assert abs(time_diff - 3600) < 5

        # Test heartbeat (normal case)
        hb_req = HeartbeatRequest(license_key=key_custom.key, device_info=device_info)
        hb_res = heartbeat(request=hb_req, db=db)
        assert hb_res["status"] == "ok"
        print("Normal heartbeat check passed.")

        print("\n--- 4. Testing Banning and Client Kick-off ---")
        # 4.1 Ban the key via PUT equivalent
        payload_update = AdminKeyUpdate(is_banned=1)
        updated_key = admin_update_key(key_id=key_id, payload=payload_update, db=db)
        assert updated_key.is_banned == 1
        print("Key successfully banned.")

        # Test heartbeat on banned key (should fail with 403)
        from fastapi import HTTPException
        try:
            heartbeat(request=hb_req, db=db)
            raise AssertionError("Heartbeat passed for banned key, but should have been rejected!")
        except HTTPException as ex:
            assert ex.status_code == 403
            print("Heartbeat check on banned key correctly rejected with 403.")

        # 4.2 Verify client activation with banned key is rejected
        try:
            activate(request=req, db=db)
            raise AssertionError("Banned key was activated, but should have been rejected!")
        except HTTPException as ex:
            assert ex.status_code == 403
            print("Attempted activation of banned key correctly rejected with 403.")

        print("\n--- 5. Testing Key Deletion ---")
        # 5.1 Delete the custom key
        admin_delete_key(key_id=key_id, db=db)
        print("Key deleted successfully.")

        # 5.2 Verify key is gone
        try:
            admin_get_key(key_id=key_id, db=db)
            raise AssertionError("Key was deleted but still retrievable!")
        except HTTPException as ex:
            assert ex.status_code == 404
            print("Key is no longer retrievable.")

        print("\nALL ADMIN API AND CUSTOM DURATION TESTS PASSED!")

    finally:
        db.close()

if __name__ == "__main__":
    test_admin_flow()
