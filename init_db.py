from sqlalchemy import create_engine
from database.models import Base
from config.settings import settings
import logging

# Configure logging
logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


def init_db():
    """Initialize the database by creating all tables."""
    try:
        # Use the sync database URL
        engine = create_engine(settings.SYNC_DATABASE_URL)

        # Create all tables
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        logger.info("Database tables created successfully!")

        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False


if __name__ == "__main__":
    success = init_db()
    if success:
        print("Database initialized successfully!")
    else:
        print("Failed to initialize database. Check the logs for details.")