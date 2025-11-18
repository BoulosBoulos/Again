from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class RoomBase(BaseModel):
    """
    Base schema for room information.

    Shared fields used when creating, reading, and updating rooms.
    """
    name: str = Field(...)
    capacity: int = Field(..., ge=1)
    equipment: Optional[str] = Field(default=None)
    location: str = Field(...)


class RoomCreate(RoomBase):
    """
    Schema for creating a new room.

    Inherits all fields from RoomBase.
    """
    pass


class RoomUpdate(BaseModel):
    """
    Schema for partial updates to a room.

    All fields are optional and only provided values will be updated.
    """
    name: Optional[str] = None
    capacity: Optional[int] = Field(default=None, ge=1)
    equipment: Optional[str] = None
    location: Optional[str] = None
    is_out_of_service: Optional[bool] = None


class RoomRead(RoomBase):
    """
    Schema returned when reading room data.

    Extends RoomBase with metadata fields such as ID and status flags.
    """
    id: int
    is_active: bool
    is_out_of_service: bool

    model_config = ConfigDict(from_attributes=True)
