# bookings_service/rate_limiter.py
import time
from typing import Dict, List, Any

from fastapi import Depends, HTTPException, status

from .auth import get_current_user_claims

WINDOW_SECONDS = 60
MAX_BOOKINGS_PER_WINDOW = 20  # example value

_user_request_log: Dict[int, List[float]] = {}


def booking_rate_limiter(claims: Dict[str, Any] = Depends(get_current_user_claims)):
    """
    Rate limit booking-related actions per authenticated user.
    """
    user_id = claims["user_id"]
    now = time.time()
    window_start = now - WINDOW_SECONDS

    timestamps = _user_request_log.get(user_id, [])
    timestamps = [ts for ts in timestamps if ts >= window_start]

    if len(timestamps) >= MAX_BOOKINGS_PER_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many booking operations in a short time",
        )

    timestamps.append(now)
    _user_request_log[user_id] = timestamps
