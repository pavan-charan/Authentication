import logging
from datetime import datetime, timezone # <--- ADD timezone import
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from config.settings import settings
from database.connection import async_engine, Base
from apps.users.schemas import UnifiedResponse
from apps.users.routes import router as users_router
from fastapi.middleware.cors import CORSMiddleware # Ensure this is explicitly imported if used globally
# --- Logging Configuration ---
logger = logging.getLogger(__name__)

def setup_app_logging():
    logging.basicConfig(
        level=logging.INFO if not settings.DEBUG else logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
        ]
    )
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

setup_app_logging()

# --- Application Lifespan Events ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Context Manager for application startup and shutdown events.
    Handles database table creation on startup and connection disposal on shutdown.
    """
    logger.info("Application startup event: Starting database initialization.")

    try:
        logger.info("Attempting to connect to the database and create tables...")
        logger.debug(f"Tables registered with Base.metadata: {list(Base.metadata.tables.keys())}")

        async with async_engine.begin() as conn:
            logger.info("Database connection established. Running Base.metadata.create_all()...")
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Base.metadata.create_all() completed.")
        logger.info("Database tables checked/created (if not existing).")
    except Exception as e:
        logger.critical(f"FATAL ERROR: Database initialization failed during startup: {e}", exc_info=True)
        raise
    finally:
        logger.info("Startup event sequence completed.")

    yield

    logger.info("Application shutdown event: Disposing database connections.")
    await async_engine.dispose()
    logger.info("Database connections disposed.")
    logger.info("Application shutdown sequence completed.")


# --- FastAPI Application Instance ---
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Your product API with authentication and more.",
    lifespan=lifespan
)

# --- Global Exception Handler for HTTPException ---
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP Exception caught globally: {exc.status_code} - {exc.detail}", exc_info=True)
    return JSONResponse(
        status_code=exc.status_code,
        content=UnifiedResponse(
            is_success=False,
            message=exc.detail,
            data=None,
            errors=[exc.detail]
        ).model_dump(mode='json')
    )

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Routers ---
app.include_router(users_router)
# --- Basic Root Endpoint ---
@app.get("/")
async def root():
    logger.info("Root endpoint accessed.")
    # Display UTC time for consistency
    return {"message": f"Welcome to {settings.PROJECT_NAME} API! The time is {datetime.now(timezone.utc).isoformat()} UTC."} # <--- CHANGE HERE