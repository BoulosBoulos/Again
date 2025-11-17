import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Use environment variable if set, else default to local Postgres
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://smart_user:smart_password@localhost:5432/smart_meeting",
)

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Yield a SQLAlchemy database session.

    This is used as a FastAPI dependency to provide a scoped
    session per request and ensure it is properly closed.

    Yields
    ------
    Session
        Active SQLAlchemy session bound to the configured engine.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
