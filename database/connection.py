# database/connection.py

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings

# Shared declarative base
Base = declarative_base()

# -------------------------------
# 🔄 Async DB Engine & Session
# -------------------------------
ASYNC_DATABASE_URL = settings.ASYNC_DATABASE_URL  # e.g. postgresql+asyncpg://...

async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.DEBUG
)

AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_async_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


# -------------------------------
# 🔁 Sync DB Engine & Session
# -------------------------------
# If not explicitly set, convert async URL to sync-compatible
SYNC_DATABASE_URL = getattr(settings, "SYNC_DATABASE_URL", ASYNC_DATABASE_URL.replace("asyncpg", "psycopg2"))

sync_engine = create_engine(SYNC_DATABASE_URL)

SyncSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=sync_engine
)

def get_sync_session():
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()
