"""
Core Rate Limiter Implementation
"""

import re
import time
from pathlib import Path
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


def is_rate_limited_sliding_window(user_id: Optional[str], ip: str, endpoint: str) -> bool:
    if user_id:
        identifier = f"user:{user_id}"
    else:
        identifier = f"ip:{ip}"
    
    if endpoint not in RATE_LIMITS:
        return False
    
    max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()

    try:
        now = time.time()
        current_window = int(now // window_seconds)
        previous_window = current_window - 1
        
        current_key = f"rate:{identifier}:{endpoint}:{current_window}"
        previous_key = f"rate:{identifier}:{endpoint}:{previous_window}"

        current_count = int(redis_client.get(current_key) or 0)
        previous_count = int(redis_client.get(previous_key) or 0)

        elapsed = now % window_seconds
        weight = (window_seconds - elapsed) / window_seconds

        effective_count = current_count + (previous_count * weight)
        
        if effective_count >= max_requests:
            return True
        
        redis_client.incr(current_key)
        redis_client.expire(current_key, window_seconds * 2)
        return False
        
    except redis.RedisError as e:
        print(f"Redis error: {e}")
        if endpoint in FAILURE_BEHAVIOR:
            if FAILURE_BEHAVIOR[endpoint] == 'fail-closed':
                return True
            else:
                return False
        return False








# Token Bucket Rate Limiter

_lua_script_path = Path(__file__).parent / 'token_bucket.lua'
with open(_lua_script_path, 'r') as f:
    token_bucket_lua = f.read()

def is_rate_limited_token_bucket(user_id: Optional[str], ip: str, endpoint: str) -> bool:
    if user_id:
        identifier = f"user:{user_id}"
    else:
        identifier = f"ip:{ip}"
    
    if endpoint not in RATE_LIMITS:
        return False
    
    max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()

    key = f"rate:{identifier}:{endpoint}"
    capacity = max_requests
    refill_rate = max_requests / window_seconds 
    cost = 1
    now = int(time.time())

    try:
        allowed = redis_client.eval(token_bucket_lua, 1, key, capacity, refill_rate, now, cost)
        if isinstance(allowed, bytes):
            allowed = int(allowed.decode('utf-8'))
        else:
            allowed = int(allowed) if allowed is not None else 0
        # Lua returns: 1 = allowed, 0 = blocked
        # We return: True = blocked, False = allowed
        return allowed == 0
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

