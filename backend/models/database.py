import logging
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Settings:
    def __init__(self):
        db_url = os.getenv("DATABASE_URL", "")
        if not db_url:
            db_url = "sqlite:///./sentinel.db"
        self.database_url = db_url
        self.llm_host = os.getenv("LLM_HOST", "http://localhost:11434")
        self.llm_model = os.getenv("LLM_MODEL", "phi:latest")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.auth_token = os.getenv("SENTINEL_AUTH_TOKEN", "")
        self.viewer_token = os.getenv("SENTINEL_VIEWER_TOKEN", "") or self.auth_token
        self.operator_token = os.getenv("SENTINEL_OPERATOR_TOKEN", "") or self.auth_token
        self.admin_token = os.getenv("SENTINEL_ADMIN_TOKEN", "") or self.operator_token

settings = Settings()

engine = create_engine(
    settings.database_url,
    poolclass=NullPool,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    try:
        try:
            from models import schemas  # noqa: F401
        except ModuleNotFoundError:
            from backend.models import schemas  # noqa: F401
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization warning: {e}")

def check_db_connection():
    try:
        with engine.connect() as conn:
            logger.info("Database connection successful")
            return True
    except Exception as e:
        logger.warning(f"Database connection issue (using fallback): {e}")
        return False
