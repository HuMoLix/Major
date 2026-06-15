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

    def is_active(self) -> bool:
        if self.is_banned == 1:
            return False
        if self.activated_at is None:
            # Not activated yet
            return True
        if self.expires_at is None:
            return False
        return datetime.datetime.utcnow() < self.expires_at

def init_db():
    Base.metadata.create_all(bind=engine)
    # 动态执行数据库迁移以增加 is_banned 和 duration_seconds 字段 (防止数据库已存在时报错)
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
    except Exception as e:
        print(f"[DB MIGRATION WARNING] {e}")

def get_db():
    db = SessionLocal()
    try:
        db.execute(Base.metadata.tables["activation_keys"].select())  # Just checks connectivity
        yield db
    except Exception:
        # Re-initialize database if tables are missing or schema changed
        init_db()
        yield db
    finally:
        db.close()
