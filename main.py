# main.py
from logging.config import dictConfig

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
# from config.logging_config import LogConfig       # uncomment if you have one
# from config.celery_config import celery_app       # adjust path if needed
# from config.sentry import sentry_logging_integration  # adjust path if needed
# from router import api_router                     # your aggregated routers

# Initialize FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    docs_url=None,     # disable in prod
    redoc_url=None     # disable in prod
)

# Optional: run Celery as root in some environments
# os.environ["C_FORCE_ROOT"] = "true"


def include_logging():
    """Configure structured logging."""
    # config = LogConfig.get_logging_config()
    # dictConfig(config)


def include_router():
    """Mount your API router."""
    # app.include_router(api_router, prefix="/api/v1")


def include_cors():
    """Enable CORS (tweak `allow_origins` in production)."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def include_sentry():
    """Initialize Sentry for error tracking."""
    # sentry_logging_integration(environment=settings.CURRENT_DEVELOPMENT_ENV)


def start_application() -> FastAPI:
    include_logging()
    include_router()
    include_cors()
    # include_sentry()  # uncomment in non-local envs
    return app


# expose the FastAPI app for Uvicorn/Gunicorn
start_application()

# expose Celery app if needed
# celery = celery_app
