from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from .database import Base


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    room_id = Column(Integer, index=True, nullable=False)
    rating = Column(Integer, nullable=False)  # 1–5
    comment = Column(Text, nullable=False)

    is_flagged = Column(Boolean, default=False)
    is_hidden = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
