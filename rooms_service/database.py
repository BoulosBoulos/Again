import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://smart_user:smart_password@localhost:5432/smart_meeting",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    Yield a SQLAlchemy database session for the Rooms service.

    This function is used as a FastAPI dependency to provide a scoped
    session per request and ensure the session is closed afterwards.

    Yields
    ------
    Session
        Active SQLAlchemy session bound to the Rooms database engine.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
