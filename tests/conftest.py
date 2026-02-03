"""
Pytest fixtures for rate limiter tests.
"""

import pytest
import time


@pytest.fixture
def redis_client():
    """Get Redis client."""
    from rate_limiter.limiter import _get_redis_client
    return _get_redis_client()


@pytest.fixture
def unique_id():
    """Generate unique identifier for test isolation."""
    return f"test_{int(time.time() * 1000000)}"


@pytest.fixture
def clean_state(redis_client):
    """Clean Redis state for a given identifier and endpoint."""
    def _clean(identifier: str, endpoint: str):
        from rate_limiter.config import DEFAULT_TRUST_SCORE, RATE_LIMITS
        
        # Reset trust score
        redis_client.set(f"trust_score:{identifier}", DEFAULT_TRUST_SCORE)
        # Clear penalty
        redis_client.delete(f"penalty:{identifier}:{endpoint}")
        # Clear rate counter
        redis_client.delete(f"rate:{identifier}:{endpoint}")
        # Clear sliding window keys
        now = time.time()
        window_seconds = RATE_LIMITS.get(endpoint, (100, 60))[1]
        for offset in range(-2, 3):
            window = int((now // window_seconds) + offset)
            redis_client.delete(f"rate:{identifier}:{endpoint}:{window}")
    return _clean
