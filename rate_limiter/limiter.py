"""
Core Rate Limiter Implementation
"""

from typing import Optional
import redis
from .config import RATE_LIMITS, FAILURE_BEHAVIOR, REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD


def is_rate_limited(user_id: Optional[str], ip: str, endpoint: str) -> bool:
    """
    Returns True if the request should be blocked.
    Returns False if the request is allowed.
    
    Args:
        user_id: User identifier if available, None otherwise
        ip: IP address (used as fallback if user_id is None)
        endpoint: The endpoint being accessed (e.g., '/login')
    
    Returns:
        True if rate limited (should block), False if allowed
    """
    if user_id:
        identifier = f"user:{user_id}"
    else:
        identifier = f"ip:{ip}"
    
    key = f"rate:{identifier}:{endpoint}"
    
    if endpoint not in RATE_LIMITS:
        return False
    
    max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()
    
    try:
        count = redis_client.incr(key)
        
        if count == 1:
            redis_client.expire(key, window_seconds)
        
        if count > max_requests:
            return True
        
        return False
    
    except redis.RedisError as e:
        print(f"Redis error: {e}")
        if endpoint in FAILURE_BEHAVIOR:
            if FAILURE_BEHAVIOR[endpoint] == 'fail-closed':
                return True
            else:
                return False
        return False


def _get_redis_client():
    """
    Helper function to get Redis client.
    """
    try:
        redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD, ssl=True, decode_responses=False)
    except redis.RedisError as e:
        raise redis.RedisError(f"Redis connection failed: {e}")
    return redis_client

