import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import DATABASE_URL, DB_MAX_OVERFLOW, DB_POOL_SIZE


def _connect_args(url: str) -> dict:
    args: dict = {}
    if "supabase" in url or os.getenv("DB_SSLMODE"):
        args["sslmode"] = os.getenv("DB_SSLMODE", "require")
    # Supabase transaction pooler (pgbouncer) no soporta prepared statements
    if "pooler.supabase.com" in url or ":6543" in url:
        args["prepare_threshold"] = 0
    return args


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    connect_args=_connect_args(DATABASE_URL),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
