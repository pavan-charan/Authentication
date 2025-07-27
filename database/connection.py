from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# ✅ IMPORTANT CHANGE: Import Base from your models module,
# where it is defined once and all models inherit from it.
from database.models import Base # <--- Changed this line

# Correct import: import the settings instance, not the module!
from config.settings import settings

# -------------------------------
# 🔄 Async DB Engine & Session
# -------------------------------
ASYNC_DATABASE_URL = settings.ASYNC_DATABASE_URL  # e.g. postgresql+asyncpg://...

async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=getattr(settings, "DEBUG", False)  # Use False if DEBUG not set
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
SYNC_DATABASE_URL = getattr(
    settings,
    "SYNC_DATABASE_URL",
    ASYNC_DATABASE_URL.replace("asyncpg", "psycopg2")
)

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
