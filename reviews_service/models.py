from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from .database import Base


class Review(Base):
    """
    SQLAlchemy model representing a room review.

    Attributes
    ----------
    id : int
        Primary key.
    user_id : int
        Identifier of the user who wrote the review.
    room_id : int
        Identifier of the room being reviewed.
    rating : int
        Numerical rating, constrained to the range 1–5.
    comment : str
        Free-text comment describing the user's experience.
    is_flagged : bool
        Whether the review has been flagged as potentially inappropriate.
    is_hidden : bool
        Whether the review is hidden from public room listings.
    created_at : datetime
        Timestamp when the review was created.
    """
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    room_id = Column(Integer, index=True, nullable=False)
    rating = Column(Integer, nullable=False)  # 1–5
    comment = Column(Text, nullable=False)

    is_flagged = Column(Boolean, default=False)
    is_hidden = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.now(timezone.utc))
