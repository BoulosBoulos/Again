from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from .database import Base


class Room(Base):
    """
    SQLAlchemy model representing a meeting room.

    Attributes
    ----------
    id : int
        Primary key.
    name : str
        Human-readable, unique room name (e.g. 'Conference Room A').
    capacity : int
        Maximum number of people the room can hold.
    equipment : str
        Optional comma-separated list of equipment (e.g. 'projector,whiteboard').
    location : str
        Physical location description (building, floor, etc.).
    is_active : bool
        Soft-delete flag; inactive rooms are hidden from normal queries.
    is_out_of_service : bool
        Whether the room is temporarily unavailable for booking.
    created_at : datetime
        Timestamp recording when the room was created.
    """
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    capacity = Column(Integer, nullable=False)
    equipment = Column(String(255), nullable=True)  # comma-separated list
    location = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_out_of_service = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
