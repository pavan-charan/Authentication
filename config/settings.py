# config/settings.py

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env at project root
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class Settings:
    # Project info
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Jatayu")
    PROJECT_VERSION: str = os.getenv("PROJECT_VERSION", "1.0.0")
    CURRENT_DEVELOPMENT_ENV: str = os.getenv("CURRENT_DEVELOPMENT_ENV", "development")

    # Database URLs
    ASYNC_DATABASE_URL: str = os.getenv("ASYNC_DATABASE_URL")
    SYNC_DATABASE_URL: str = os.getenv(
        "SYNC_DATABASE_URL",
        ASYNC_DATABASE_URL.replace("asyncpg", "psycopg2") if ASYNC_DATABASE_URL else None,
    )

    # Redis (for Celery broker & backend)
    REDIS_URL: str = os.getenv("REDIS_URL")

    # Celery configs
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Sentry (optional)
    SENTRY_DSN: str = os.getenv("SENTRY_DSN", "")

    # CORS settings: comma separated list or '*'
    CORS_ORIGINS: list[str] = [
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    ]

    # Security & JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


# single instance to import elsewhere
settings = Settings()
