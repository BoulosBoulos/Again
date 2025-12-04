# common/cache.py
import json
import os
from typing import Any, Optional

import redis


_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> Optional[redis.Redis]:
    """
    Return a Redis client if REDIS_URL is configured, otherwise None.
    Fails gracefully (no caching) if Redis is not reachable.
    """
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return None

    try:
        client = redis.from_url(redis_url, decode_responses=True)
        # Lightweight health check
        client.ping()
    except Exception:
        # If Redis is down or not reachable, just disable caching
        _redis_client = None
        return None

    _redis_client = client
    return _redis_client


def get_cached_json(key: str) -> Optional[Any]:
    client = get_redis_client()
    if client is None:
        return None

    raw = client.get(key)
    if raw is None:
        return None
    return json.loads(raw)


def set_cached_json(key: str, value: Any, ttl_seconds: int = 60) -> None:
    client = get_redis_client()
    if client is None:
        return

    client.setex(key, ttl_seconds, json.dumps(value, default=str))


def delete_prefix(prefix: str) -> None:
    """
    Delete all keys starting with prefix.
    Example: prefix='user:42' or 'rooms:availability:'.
    """
    client = get_redis_client()
    if client is None:
        return

    pattern = prefix + "*"
    for k in client.scan_iter(pattern):
        client.delete(k)
