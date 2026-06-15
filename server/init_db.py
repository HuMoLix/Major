import datetime
from db import init_db, SessionLocal, ActivationKey

def seed_database():
    init_db()
    db = SessionLocal()
    try:
        # Check if we already have licenses
        if db.query(ActivationKey).count() > 0:
            print("Database already seeded.")
            return

        print("Seeding test licenses...")
        
        # 1. Standard 30-day key (not activated yet)
        key_30d = ActivationKey(
            key="TEST-KEY-30DAYS",
            activation_days=30,
        )
        
        # 2. Family/Multi-device 365-day key
        key_365d = ActivationKey(
            key="TEST-KEY-365DAYS",
            activation_days=365,
        )
        
        # 3. Already expired key
        key_expired = ActivationKey(
            key="EXPIRED-KEY-TEST",
            activation_days=0,
            device_info="TEST-DEVICE-FINGERPRINT",
            activated_at=datetime.datetime.utcnow() - datetime.timedelta(days=10),
            expires_at=datetime.datetime.utcnow() - datetime.timedelta(days=10) # Expired 10 days ago
        )

        db.add_all([key_30d, key_365d, key_expired])
        db.commit()
        print("Test licenses seeded successfully:")
        print(" - TEST-KEY-30DAYS (30 Days)")
        print(" - TEST-KEY-365DAYS (365 Days)")
        print(" - EXPIRED-KEY-TEST (Expired)")
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
