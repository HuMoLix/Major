import datetime
import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, event
from sqlalchemy.orm import declarative_base, sessionmaker

# 动态获取当前脚本所在文件夹的绝对路径，实现跨平台兼容
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'vpn.db')}"

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class ActivationKey(Base):
    __tablename__ = "activation_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, unique=True, index=True, nullable=False)
    activation_days = Column(Integer, nullable=False)
    device_info = Column(String, nullable=True)  # SHA-256 Hardware ID of the activated machine
    
    # WireGuard dynamic connection parameters
    client_pubkey = Column(String, nullable=True)
    assigned_ip = Column(String, nullable=True)
    
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_banned = Column(Integer, default=0) # 0 = normal, 1 = banned
    duration_seconds = Column(Integer, nullable=True) # Custom duration in seconds (optional)
    traffic_limit = Column(Integer, nullable=True) # in bytes (optional)
    traffic_used = Column(Integer, default=0) # in bytes
    speed_limit = Column(Integer, nullable=True) # in Mbps (optional)
    app_traffic_json = Column(String, nullable=True) # JSON string of Top 10 app traffic

    def is_active(self) -> bool:
        if self.is_banned == 1:
            return False
        if self.activated_at is None:
            # Not activated yet
            return True
        if self.expires_at is None:
            return False
        # Also check traffic limit if present
        if self.traffic_limit is not None and self.traffic_used >= self.traffic_limit:
            return False
        return datetime.datetime.utcnow() < self.expires_at

def init_db():
    Base.metadata.create_all(bind=engine)
    # 动态执行数据库迁移以增加新字段 (防止数据库已存在时报错)
    try:
        with engine.begin() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(activation_keys)").fetchall()
            columns = [r[1] for r in result]
            if "is_banned" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN is_banned INTEGER DEFAULT 0")
                print("[DB] Successfully migrated database to add is_banned column.")
            if "duration_seconds" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN duration_seconds INTEGER")
                print("[DB] Successfully migrated database to add duration_seconds column.")
            if "traffic_limit" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN traffic_limit INTEGER")
                print("[DB] Successfully migrated database to add traffic_limit column.")
            if "traffic_used" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN traffic_used INTEGER DEFAULT 0")
                print("[DB] Successfully migrated database to add traffic_used column.")
            if "speed_limit" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN speed_limit INTEGER")
                print("[DB] Successfully migrated database to add speed_limit column.")
            if "app_traffic_json" not in columns:
                conn.exec_driver_sql("ALTER TABLE activation_keys ADD COLUMN app_traffic_json TEXT")
                print("[DB] Successfully migrated database to add app_traffic_json column.")
    except Exception as e:
        print(f"[DB MIGRATION WARNING] {e}")

def get_db():
    db = SessionLocal()
    try:
        db.execute(Base.metadata.tables["activation_keys"].select())  # Just checks connectivity
    except Exception:
        # Re-initialize database if tables are missing or schema changed
        try:
            init_db()
        except Exception as e:
            print(f"[DB INIT ERROR] {e}")
    try:
        yield db
    finally:
        db.close()
