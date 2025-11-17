from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import Column, DateTime, Enum, Integer

from .database import Base


class BookingStatus(str, PyEnum):
    """
    Enumeration of possible booking statuses.

    Values
    ------
    pending
        Booking has been created but not yet confirmed.
    confirmed
        Booking is active and holds the room for the given time range.
    cancelled
        Booking has been cancelled and should not block the room.
    """
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"


class Booking(Base):
    """
    SQLAlchemy model representing a room booking.

    Attributes
    ----------
    id : int
        Primary key.
    user_id : int
        Identifier of the user who owns the booking.
    room_id : int
        Identifier of the booked room.
    start_time : datetime
        Start of the reserved time interval.
    end_time : datetime
        End of the reserved time interval.
    status : BookingStatus
        Current status of the booking (pending/confirmed/cancelled).
    created_at : datetime
        Timestamp when the booking was created.
    """
    __tablename__ = "bookings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    room_id = Column(Integer, index=True, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    status = Column(Enum(BookingStatus), nullable=False, default=BookingStatus.CONFIRMED)
    created_at = Column(DateTime, default=datetime.utcnow)
