from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ReviewBase(BaseModel):
    room_id: int = Field(..., ge=1, example=1)
    rating: int = Field(..., ge=1, le=5, example=4)
    comment: str = Field(..., min_length=1, max_length=1000)

    @field_validator("comment")
    @classmethod
    def strip_comment(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("comment must not be empty")
        return v


class ReviewCreate(ReviewBase):
    pass


class ReviewUpdate(BaseModel):
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    comment: Optional[str] = Field(default=None, min_length=1, max_length=1000)

    @field_validator("comment")
    @classmethod
    def strip_comment(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("comment must not be empty")
        return v


class ReviewRead(ReviewBase):
    id: int
    user_id: int
    is_flagged: bool
    is_hidden: bool
    created_at: datetime

    class Config:
        from_attributes = True
