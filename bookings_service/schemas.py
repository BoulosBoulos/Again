from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .models import BookingStatus


class BookingBase(BaseModel):
    room_id: int = Field(..., ge=1, example=1)
    start_time: datetime = Field(..., example="2025-01-01T09:00:00")
    end_time: datetime = Field(..., example="2025-01-01T10:00:00")


class BookingCreate(BookingBase):
    pass


class BookingUpdate(BaseModel):
    room_id: Optional[int] = Field(default=None, ge=1)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: Optional[BookingStatus] = None


class BookingRead(BookingBase):
    id: int
    user_id: int
    status: BookingStatus
    created_at: datetime

    class Config:
        from_attributes = True
