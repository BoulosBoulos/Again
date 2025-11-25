# users_service/rate_limiter.py
import time, os
from typing import Dict, List

from fastapi import HTTPException, Request, status

# Simple sliding-window rate limiter: N requests / WINDOW seconds per IP+path
WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 10

_request_log: Dict[str, List[float]] = {}


def ip_rate_limiter(request: Request):
    """
    Rate limit based on client IP + path.

    Used for unauthenticated endpoints like:
    - POST /api/v1/users/register
    - POST /api/v1/users/login
    """
    # ❗ Skip rate limiting completely in automated tests
    if os.getenv("TESTING") == "1":
        return
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{request.url.path}"

    now = time.time()
    window_start = now - WINDOW_SECONDS

    timestamps = _request_log.get(key, [])
    # keep only timestamps inside the window
    timestamps = [ts for ts in timestamps if ts >= window_start]

    if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests from this IP, please slow down",
        )

    timestamps.append(now)
    _request_log[key] = timestamps