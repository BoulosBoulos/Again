from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, ConfigDict


class ReviewBase(BaseModel):
    """
    Base schema for review content.

    Includes the target room, rating, and comment text, along with
    basic validation and sanitization for the comment field.
    """
    room_id: int = Field(..., ge=1)
    rating: int = Field(..., ge=1, le=5)
    comment: str = Field(..., min_length=1, max_length=1000)

    @field_validator("comment")
    @classmethod
    def strip_comment(cls, v: str) -> str:
        """
        Normalize and validate the comment field.

        - Strips leading/trailing whitespace.
        - Rejects empty comments after stripping.
        """
        v = v.strip()
        if not v:
            raise ValueError("comment must not be empty")
        return v


class ReviewCreate(ReviewBase):
    """
    Schema for creating a new review.

    Reuses all fields and validation rules from ReviewBase.
    """
    pass


class ReviewUpdate(BaseModel):
    """
    Schema for partially updating an existing review.

    All fields are optional; when present they are validated in the
    same way as on creation.
    """
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    comment: Optional[str] = Field(default=None, min_length=1, max_length=1000)

    @field_validator("comment")
    @classmethod
    def strip_comment(cls, v: str) -> str:
        """
        Normalize and validate the updated comment text.

        - Strips leading/trailing whitespace.
        - Rejects empty comments after stripping.
        """
        v = v.strip()
        if not v:
            raise ValueError("comment must not be empty")
        return v


class ReviewRead(ReviewBase):
    """
    Schema returned when reading review data.

    Extends ReviewBase with identifiers and moderation flags.
    """
    id: int
    user_id: int
    is_flagged: bool
    is_hidden: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
