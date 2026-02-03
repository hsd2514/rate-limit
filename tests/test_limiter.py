"""
Rate Limiter Test Suite

Production Config:
- /login: limit=5, cost=2 → 2 requests allowed (3rd blocked: 3*2=6>5)
- /search: limit=20, cost=5 → 4 requests allowed (5th blocked: 5*5=25>20)
- /read: limit=100, cost=1 → 100 requests allowed
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock
import redis

from rate_limiter.limiter import (
    is_rate_limited,
    is_rate_limited_sliding_window,
    is_rate_limited_token_bucket,
    _get_redis_client,
    _get_trust_score,
    _compute_final_capacity,
)
from rate_limiter.config import DEFAULT_TRUST_SCORE, TRUST_SCORE_MIN, TRUST_SCORE_MAX


# =============================================================================
# BASIC CORRECTNESS
# =============================================================================

class TestBasicCorrectness:
    
    def test_allows_under_limit(self, unique_id, clean_state):
        """Requests under limit should pass."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"  # 2 allowed
        clean_state(identifier, endpoint)
        
        r1 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False, "1st should be allowed"
        assert r2 is False, "2nd should be allowed"
    
    def test_blocks_over_limit(self, unique_id, clean_state):
        """Requests over limit should be blocked."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"  # 2 allowed, 3rd blocked
        clean_state(identifier, endpoint)
        
        is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r3 is True, "3rd should be blocked"
    
    def test_window_reset(self, unique_id, clean_state, redis_client):
        """After window reset, requests should be allowed."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        # Hit limit
        for _ in range(3):
            is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        # Reset
        redis_client.delete(f"rate:{identifier}:{endpoint}")
        clean_state(identifier, endpoint)
        
        result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        assert result is False, "Should be allowed after reset"
    
    def test_unknown_endpoint_allowed(self, unique_id):
        """Unknown endpoints pass through."""
        result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint="/unknown")
        assert result is False


# =============================================================================
# IDENTITY & TIERS
# =============================================================================

class TestIdentityAndTiers:
    
    def test_user_takes_precedence(self, unique_id, clean_state, redis_client):
        """User ID used when provided."""
        clean_state(f"user:{unique_id}", "/login")
        
        is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint="/login")
        
        assert redis_client.get(f"rate:user:{unique_id}:/login") is not None
        assert redis_client.get(f"rate:ip:1.1.1.1:/login") is None
    
    def test_ip_when_no_user(self, clean_state, redis_client):
        """IP used when user_id is None."""
        ip = f"10.0.{int(time.time()) % 255}.1"
        clean_state(f"ip:{ip}", "/login")
        
        is_rate_limited(user_id=None, ip=ip, endpoint="/login")
        
        assert redis_client.get(f"rate:ip:{ip}:/login") is not None
    
    def test_separate_counters(self, clean_state):
        """Different users have separate counters."""
        u1 = f"u1_{int(time.time() * 1000)}"
        u2 = f"u2_{int(time.time() * 1000)}"
        
        clean_state(f"user:{u1}", "/login")
        clean_state(f"user:{u2}", "/login")
        
        # User 1 hits limit
        for _ in range(3):
            is_rate_limited(user_id=u1, ip="1.1.1.1", endpoint="/login")
        
        # User 2 still allowed
        result = is_rate_limited(user_id=u2, ip="1.1.1.1", endpoint="/login")
        assert result is False
    
    def test_pro_tier_higher_limit(self, unique_id, clean_state):
        """Pro tier gets 5x limit."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"  # base=5, pro=25, cost=2 → 12 allowed
        clean_state(identifier, endpoint)
        
        # Should allow 10+ requests as pro
        for i in range(10):
            result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint, tier="pro")
            assert result is False, f"Pro request {i+1} should pass"


# =============================================================================
# COST-BASED
# =============================================================================

class TestCostBased:
    
    def test_high_cost_fewer_requests(self, unique_id, clean_state):
        """/search (cost=5, limit=20) allows 4 requests."""
        identifier = f"user:{unique_id}"
        endpoint = "/search"
        clean_state(identifier, endpoint)
        
        for i in range(4):
            result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
            assert result is False, f"Request {i+1} should pass"
        
        result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        assert result is True, "5th should be blocked"
    
    def test_low_cost_more_requests(self, unique_id, clean_state):
        """/login (cost=2, limit=5) allows 2 requests."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        r1 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False
        assert r3 is True


# =============================================================================
# PENALTY
# =============================================================================

class TestPenalty:
    
    def test_penalty_on_block(self, unique_id, clean_state, redis_client):
        """Penalty increases when blocked."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        for _ in range(3):
            is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        penalty = int(redis_client.get(f"penalty:{identifier}:{endpoint}") or 0)
        assert penalty >= 1
    
    def test_penalty_reduces_capacity(self, unique_id, clean_state, redis_client):
        """Penalty reduces effective limit."""
        identifier = f"user:{unique_id}"
        endpoint = "/search"  # limit=20, penalty_step=5
        clean_state(identifier, endpoint)
        
        # penalty=2 → limit=20-10=10, cost=5 → 2 allowed
        redis_client.set(f"penalty:{identifier}:{endpoint}", 2)
        
        r1 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False
        assert r3 is True
    
    def test_capacity_min_one(self):
        """Capacity never below 1."""
        cap = _compute_final_capacity(5, 'free', 100, 1.0)
        assert cap >= 1


# =============================================================================
# TRUST SCORE
# =============================================================================

class TestTrustScore:
    
    def test_default_trust(self, unique_id, clean_state):
        """New clients start at default."""
        clean_state(f"user:{unique_id}", "/login")
        score = _get_trust_score(f"user:{unique_id}")
        assert score == DEFAULT_TRUST_SCORE
    
    def test_trust_clamped(self, redis_client):
        """Trust clamped to bounds."""
        identifier = f"user:clamp_{int(time.time())}"
        
        redis_client.set(f"trust_score:{identifier}", 10.0)
        assert _get_trust_score(identifier) == TRUST_SCORE_MAX
        
        redis_client.set(f"trust_score:{identifier}", 0.1)
        assert _get_trust_score(identifier) == TRUST_SCORE_MIN
    
    def test_high_trust_more_capacity(self, unique_id, clean_state, redis_client):
        """High trust = more requests."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"  # limit=5
        clean_state(identifier, endpoint)
        
        # trust=1.5 → limit=7, cost=2 → 3 allowed
        redis_client.set(f"trust_score:{identifier}", 1.5)
        
        r1 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False and r3 is False
    
    def test_low_trust_less_capacity(self, unique_id, clean_state, redis_client):
        """Low trust = fewer requests."""
        identifier = f"user:{unique_id}"
        endpoint = "/search"  # limit=20
        clean_state(identifier, endpoint)
        
        # trust=0.5 → limit=10, cost=5 → 2 allowed
        redis_client.set(f"trust_score:{identifier}", 0.5)
        
        r1 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False
        assert r3 is True


# =============================================================================
# SLIDING WINDOW
# =============================================================================

class TestSlidingWindow:
    
    def test_allows_under_limit(self, unique_id, clean_state):
        """Allows requests under limit."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        r1 = is_rate_limited_sliding_window(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited_sliding_window(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False
    
    def test_blocks_over_limit(self, unique_id, clean_state):
        """Blocks when over limit."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        is_rate_limited_sliding_window(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        is_rate_limited_sliding_window(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited_sliding_window(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r3 is True


# =============================================================================
# TOKEN BUCKET
# =============================================================================

class TestTokenBucket:
    
    def test_allows_burst(self, unique_id, clean_state):
        """Allows burst up to capacity."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        r1 = is_rate_limited_token_bucket(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r2 = is_rate_limited_token_bucket(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r1 is False and r2 is False
    
    def test_blocks_empty(self, unique_id, clean_state):
        """Blocks when bucket empty."""
        identifier = f"user:{unique_id}"
        endpoint = "/login"
        clean_state(identifier, endpoint)
        
        is_rate_limited_token_bucket(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        is_rate_limited_token_bucket(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        r3 = is_rate_limited_token_bucket(user_id=unique_id, ip="1.1.1.1", endpoint=endpoint)
        
        assert r3 is True


# =============================================================================
# FAILURE MODES
# =============================================================================

class TestFailureModes:
    
    def test_fail_closed(self, unique_id):
        """/login (fail-closed) blocks on error."""
        from rate_limiter import limiter
        
        mock = MagicMock()
        # Allow reads for penalty/trust, fail on write
        mock.get.return_value = None
        mock.incrby.side_effect = redis.RedisError("Fail")
        
        with patch.object(limiter, '_get_redis_client', return_value=mock):
            result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint="/login")
            assert result is True
    
    def test_fail_open(self, unique_id):
        """/search (fail-open) allows on error."""
        from rate_limiter import limiter
        
        mock = MagicMock()
        # Allow reads for penalty/trust, fail on write
        mock.get.return_value = None
        mock.incrby.side_effect = redis.RedisError("Fail")
        
        with patch.object(limiter, '_get_redis_client', return_value=mock):
            result = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint="/search")
            assert result is False


# =============================================================================
# CONCURRENCY
# =============================================================================

class TestConcurrency:
    
    def test_concurrent_limit(self, unique_id, clean_state):
        """Concurrent requests respect limit."""
        clean_state(f"user:{unique_id}", "/login")  # 2 allowed
        
        results = []
        
        def req():
            r = is_rate_limited(user_id=unique_id, ip="1.1.1.1", endpoint="/login")
            results.append(r)
        
        threads = [threading.Thread(target=req) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        allowed = sum(1 for r in results if r is False)
        assert allowed <= 2, f"Max 2 allowed, got {allowed}"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

class TestHelpers:
    
    def test_basic(self):
        assert _compute_final_capacity(100, 'free', 0, 1.0) == 100
    
    def test_tier(self):
        assert _compute_final_capacity(100, 'pro', 0, 1.0) == 500
    
    def test_penalty(self):
        # 100 - 2*5 = 90
        assert _compute_final_capacity(100, 'free', 2, 1.0) == 90
    
    def test_trust(self):
        assert _compute_final_capacity(100, 'free', 0, 1.5) == 150
    
    def test_min_one(self):
        assert _compute_final_capacity(5, 'free', 100, 0.5) >= 1
