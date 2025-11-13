from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Enum

from .database import Base


class UserRole(str, PyEnum):
    ADMIN = "admin"
    REGULAR = "regular"
    FACILITY_MANAGER = "facility_manager"
    MODERATOR = "moderator"
    AUDITOR = "auditor"
    SERVICE_ACCOUNT = "service_account"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.REGULAR)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
