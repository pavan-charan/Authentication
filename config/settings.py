# config/settings.py

import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()


class Settings:
    # Project info
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Jatayu")
    PROJECT_VERSION: str = os.getenv("PROJECT_VERSION", "1.0.0")
    CURRENT_ENV: str = os.getenv("CURRENT_DEVELOPMENT_ENV", "development")

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
    SMTP_EMAIL: str = os.getenv("SMTP_EMAIL")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "")
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", SMTP_EMAIL)
settings = Settings()