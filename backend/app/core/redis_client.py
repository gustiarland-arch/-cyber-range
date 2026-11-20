"""Redis is used only for cache, queues, rate limiting counters and realtime fan-out."""
import time
from functools import lru_cache
from threading import Lock

import redis

from app.core.config import get_settings
from app.core.logging import log


@lru_cache
def get_redis() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, socket_timeout=1, socket_connect_timeout=1, decode_responses=True)


class RateLimiter:
    """Fixed-window limiter in Redis; falls back to an in-process window if Redis is unavailable."""

    def __init__(self) -> None:
        self._local: dict[str, tuple[int, float]] = {}
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Register one hit. Returns True if allowed."""
        try:
            r = get_redis()
            k = f"rl:{key}"
            pipe = r.pipeline()
            pipe.incr(k)
            pipe.expire(k, window, nx=True)
            count, _ = pipe.execute()
            return int(count) <= limit
        except redis.RedisError:
            log.warning("rate_limiter_redis_unavailable_fallback_local")
            now = time.monotonic()
            with self._lock:
                count, start = self._local.get(key, (0, now))
                if now - start > window:
                    count, start = 0, now
                count += 1
                self._local[key] = (count, start)
                return count <= limit

    def reset(self, key: str) -> None:
        try:
            get_redis().delete(f"rl:{key}")
        except redis.RedisError:
            pass
        with self._lock:
            self._local.pop(key, None)


rate_limiter = RateLimiter()
