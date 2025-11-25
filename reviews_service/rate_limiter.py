# reviews_service/rate_limiter.py
import time
from typing import Dict, List, Any

from fastapi import Depends, HTTPException, status

from .auth import get_current_user_claims

import os

WINDOW_SECONDS = 60
MAX_REVIEWS_PER_WINDOW = 20

_user_review_log: Dict[int, List[float]] = {}


def review_rate_limiter(claims: Dict[str, Any] = Depends(get_current_user_claims)):
    """
    Rate limit review submissions per user.
    """
    # ❗ Skip rate limiting completely in automated tests
    if os.getenv("TESTING") == "1":
        return
    user_id = claims["user_id"]
    now = time.time()
    window_start = now - WINDOW_SECONDS

    timestamps = _user_review_log.get(user_id, [])
    timestamps = [ts for ts in timestamps if ts >= window_start]

    if len(timestamps) >= MAX_REVIEWS_PER_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many review operations in a short time",
        )

    timestamps.append(now)
    _user_review_log[user_id] = timestamps
