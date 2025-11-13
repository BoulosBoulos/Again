from typing import Optional

from pydantic import BaseModel, Field


class RoomBase(BaseModel):
    name: str = Field(..., example="Conference Room A")
    capacity: int = Field(..., ge=1, example=10)
    equipment: Optional[str] = Field(
        default=None,
        example="projector,whiteboard,video-conference",
    )
    location: str = Field(..., example="Building A - Floor 3")


class RoomCreate(RoomBase):
    pass


class RoomUpdate(BaseModel):
    name: Optional[str] = None
    capacity: Optional[int] = Field(default=None, ge=1)
    equipment: Optional[str] = None
    location: Optional[str] = None
    is_out_of_service: Optional[bool] = None


class RoomRead(RoomBase):
    id: int
    is_active: bool
    is_out_of_service: bool

    class Config:
        from_attributes = True  # pydantic v2
