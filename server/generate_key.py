import argparse
import random
import string
from db import SessionLocal, ActivationKey, init_db

def generate_random_key() -> str:
    """Generates a readable key like KEY-ABCD-EFGH-IJKL-MNOP"""
    segments = []
    for _ in range(4):
        seg = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
        segments.append(seg)
    return "KEY-" + "-".join(segments)

def main():
    parser = argparse.ArgumentParser(description="Admin Activation Key Generator")
    parser.add_argument("--days", type=int, default=30, help="Activation duration in days")
    parser.add_argument("--count", type=int, default=1, help="Number of keys to generate")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        print(f"Generating {args.count} activation key(s) with {args.days} days duration...")
        for _ in range(args.count):
            key_str = generate_random_key()
            new_key = ActivationKey(
                key=key_str,
                activation_days=args.days
            )
            db.add(new_key)
            db.commit()
            print(f"Generated Key: {key_str} ({args.days} Days)")
    except Exception as e:
        print(f"Error generating keys: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    main()
