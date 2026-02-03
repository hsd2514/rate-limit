"""
Core Rate Limiter Implementation
"""

import re
import time
from pathlib import Path
from typing import Optional
import redis
from .config import RATE_LIMITS, FAILURE_BEHAVIOR, REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD , TIER_MULTIPLIERS , PENALTY_STEP, PENALTY_TTL_SECONDS, ENDPOINT_COST , DEFAULT_TRUST_SCORE, TRUST_SCORE_MIN, TRUST_SCORE_MAX, TRUST_SCORE_INCREMENT, TRUST_SCORE_DECREMENT, TRUST_SCORE_TTL, TRUST_SCORE_THRESHOLD


def _compute_final_capacity(
    base_limit: int,
    tier: str,
    penalty: int,
    trust_score: float
) -> int:
    """
    Compute final capacity after applying tier multiplier, penalty, and trust score.
    Ensures capacity is always at least 1.
    """
    tier_multiplier = TIER_MULTIPLIERS.get(tier, 1)
    limit = int(base_limit * tier_multiplier)
    limit -= penalty * PENALTY_STEP
    limit = max(1, limit)
    limit = int(limit * trust_score)
    return max(1, limit)


def is_rate_limited(user_id: Optional[str], ip: str, endpoint: str , tier: Optional[str] = None) -> bool:
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
    
    
    if tier is None:
        tier = 'anonymous' if user_id is None else 'free'
    


    

    key = f"rate:{identifier}:{endpoint}"
    
    if endpoint not in RATE_LIMITS:
        return False
    
    request_cost = ENDPOINT_COST.get(endpoint, 1)
   
    base_max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()
    penalty_key = f"penalty:{identifier}:{endpoint}"
    penalty = int(redis_client.get(penalty_key) or 0)
    
    trust_score = _get_trust_score(identifier)
    final_capacity = _compute_final_capacity(base_max_requests, tier, penalty, trust_score)

    # NOTE:
    # Trust score and penalty updates are not atomic with rate checks.
    # In a production system, this logic would be moved into Redis Lua
    # scripts to ensure consistency under concurrency.
    
    try:
        count = redis_client.incrby(key, request_cost)
        
        if count == request_cost:
            redis_client.expire(key, window_seconds)
        
        if count > final_capacity:
            redis_client.incr(penalty_key)
            redis_client.expire(penalty_key, PENALTY_TTL_SECONDS)
            _decrement_trust_score(identifier)
            return True
        
        if count < final_capacity * TRUST_SCORE_THRESHOLD:
            _increment_trust_score(identifier)
        return False
    
    except redis.RedisError as e:
        print(f"Redis error: {e}")
        if endpoint in FAILURE_BEHAVIOR:
            if FAILURE_BEHAVIOR[endpoint] == 'fail-closed':
                return True
            else:
                return False
        return False


def is_rate_limited_sliding_window(user_id: Optional[str], ip: str, endpoint: str , tier: Optional[str] = None) -> bool:
    if user_id:
        identifier = f"user:{user_id}"
    else:
        identifier = f"ip:{ip}"
    
    if tier is None:
        tier = 'anonymous' if user_id is None else 'free'
    
    if endpoint not in RATE_LIMITS:
        return False

    request_cost = ENDPOINT_COST.get(endpoint, 1)
    base_max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()
    penalty_key = f"penalty:{identifier}:{endpoint}"
    penalty = int(redis_client.get(penalty_key) or 0)
    
    trust_score = _get_trust_score(identifier)
    final_capacity = _compute_final_capacity(base_max_requests, tier, penalty, trust_score)

    # NOTE:
    # Trust score and penalty updates are not atomic with rate checks.
    # In a production system, this logic would be moved into Redis Lua
    # scripts to ensure consistency under concurrency.

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
        projected_count = effective_count + request_cost
        
        if projected_count >= final_capacity:
            redis_client.incr(penalty_key)
            redis_client.expire(penalty_key, PENALTY_TTL_SECONDS)
            _decrement_trust_score(identifier)
            return True
        
        redis_client.incrby(current_key, request_cost)
        redis_client.expire(current_key, window_seconds * 2)
        if effective_count < final_capacity * TRUST_SCORE_THRESHOLD:
            _increment_trust_score(identifier)
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

def is_rate_limited_token_bucket(user_id: Optional[str], ip: str, endpoint: str , tier: Optional[str] = None) -> bool:
    if user_id:
        identifier = f"user:{user_id}"
    else:
        identifier = f"ip:{ip}"
    
    if tier is None:
        tier = 'anonymous' if user_id is None else 'free'
    
    if endpoint not in RATE_LIMITS:
        return False
    
    request_cost = ENDPOINT_COST.get(endpoint, 1)
    base_max_requests, window_seconds = RATE_LIMITS[endpoint]
    redis_client = _get_redis_client()
    penalty_key = f"penalty:{identifier}:{endpoint}"
    penalty = int(redis_client.get(penalty_key) or 0)
    
    trust_score = _get_trust_score(identifier)
    final_capacity = _compute_final_capacity(base_max_requests, tier, penalty, trust_score)

    # NOTE:
    # Trust score and penalty updates are not atomic with rate checks.
    # In a production system, this logic would be moved into Redis Lua
    # scripts to ensure consistency under concurrency.

    key = f"rate:{identifier}:{endpoint}"
    capacity = int(final_capacity)
    refill_rate = final_capacity / window_seconds 
    cost = request_cost
    now = int(time.time())

    try:
        allowed = redis_client.eval(token_bucket_lua, 1, key, capacity, refill_rate, now, cost)
        if isinstance(allowed, bytes):
            allowed = int(allowed.decode('utf-8'))
        else:
            allowed = int(allowed) if allowed is not None else 0
        # Lua returns: 1 = allowed, 0 = blocked
        # We return: True = blocked, False = allowed
        is_blocked = allowed == 0
        if is_blocked:
            _decrement_trust_score(identifier)
        else:
            _increment_trust_score(identifier)
        return is_blocked
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

def _get_trust_score(identifier: str) -> float:
    redis_client = _get_redis_client()
    trust_score_key = f"trust_score:{identifier}"
    trust_score = float(redis_client.get(trust_score_key) or DEFAULT_TRUST_SCORE)
    return max(TRUST_SCORE_MIN, min(TRUST_SCORE_MAX, trust_score))

def _increment_trust_score(identifier: str) -> None:
    redis_client = _get_redis_client()
    trust_score_key = f"trust_score:{identifier}"
    try:
        new_score = redis_client.incrbyfloat(trust_score_key, TRUST_SCORE_INCREMENT)
        clamped_score = max(TRUST_SCORE_MIN, min(TRUST_SCORE_MAX, new_score))
        redis_client.set(trust_score_key, clamped_score)
        redis_client.expire(trust_score_key, TRUST_SCORE_TTL)
    except redis.RedisError:
        pass

def _decrement_trust_score(identifier: str) -> None:
    redis_client = _get_redis_client()
    trust_score_key = f"trust_score:{identifier}"
    try:
        new_score = redis_client.incrbyfloat(trust_score_key, -TRUST_SCORE_DECREMENT)
        clamped_score = max(TRUST_SCORE_MIN, min(TRUST_SCORE_MAX, new_score))
        redis_client.set(trust_score_key, clamped_score)
        redis_client.expire(trust_score_key, TRUST_SCORE_TTL)
    except redis.RedisError:
        pass