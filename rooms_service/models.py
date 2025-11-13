from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from .database import Base


class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    capacity = Column(Integer, nullable=False)
    equipment = Column(String(255), nullable=True)  # comma-separated list
    location = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_out_of_service = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
