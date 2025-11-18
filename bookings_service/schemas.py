from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict

from .models import BookingStatus


class BookingBase(BaseModel):
    """
    Base schema for booking time and room information.

    Shared fields used across booking create and read operations.
    """
    room_id: int = Field(..., ge=1)
    start_time: datetime = Field(...)
    end_time: datetime = Field(...)


class BookingCreate(BookingBase):
    """
    Schema for creating a new booking.

    Inherits room_id, start_time, and end_time from BookingBase.
    """
    pass


class BookingUpdate(BaseModel):
    """
    Schema for partially updating an existing booking.

    All fields are optional; only provided values will be applied.
    """
    room_id: Optional[int] = Field(default=None, ge=1)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: Optional[BookingStatus] = None


class BookingRead(BookingBase):
    """
    Schema returned when reading booking information.

    Extends BookingBase with identifiers, status, and creation timestamp.
    """
    id: int
    user_id: int
    status: BookingStatus
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
