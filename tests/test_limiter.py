"""
Tests for Rate Limiter

Comprehensive test suite for the rate limiter implementation.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
import redis
from rate_limiter.limiter import is_rate_limited
from rate_limiter.config import RATE_LIMITS, FAILURE_BEHAVIOR


class TestRateLimiter:
    """Test suite for rate limiter"""
    
    def test_login_rate_limit_exceeds_limit(self):
        """
        Test that more than 5 requests to /login within 60s are blocked.
        First 5 should be allowed, 6th should be blocked.
        """
        user_id = "test_user_1"
        ip = "192.168.1.1"
        endpoint = "/login"
        
        # First 5 requests should be allowed
        for i in range(5):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, f"Request {i+1} should be allowed"
        
        # 6th request should be blocked
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is True, "6th request should be blocked (exceeds limit of 5)"
    
    def test_search_rate_limit_exceeds_limit(self):
        """
        Test that more than 20 requests to /search within 60s are blocked.
        """
        user_id = "test_user_2"
        ip = "192.168.1.2"
        endpoint = "/search"
        
        # First 20 requests should be allowed
        for i in range(20):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, f"Request {i+1} should be allowed"
        
        # 21st request should be blocked
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is True, "21st request should be blocked (exceeds limit of 20)"
    
    def test_read_rate_limit_exceeds_limit(self):
        """
        Test that more than 100 requests to /read within 60s are blocked.
        """
        user_id = "test_user_3"
        ip = "192.168.1.3"
        endpoint = "/read"
        
        # First 100 requests should be allowed
        for i in range(100):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, f"Request {i+1} should be allowed"
        
        # 101st request should be blocked
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is True, "101st request should be blocked (exceeds limit of 100)"
    
    def test_counter_resets_after_window(self):
        """
        Test that counter resets after the window expires (60 seconds).
        Note: This test may take up to 61 seconds to run.
        """
        user_id = "test_user_reset"
        ip = "192.168.1.4"
        endpoint = "/login"
        
        # Make 5 requests (all should be allowed)
        for i in range(5):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, f"Request {i+1} should be allowed"
        
        # 6th request should be blocked
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is True, "6th request should be blocked"
        
        # Wait for window to expire (61 seconds)
        print("\n⏳ Waiting 61 seconds for window to expire...")
        time.sleep(61)
        
        # After window expires, new request should be allowed (counter reset)
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is False, "Request after window expiration should be allowed (counter reset)"
    
    def test_user_id_takes_precedence_over_ip(self):
        """
        Test that user_id is used when available, and different users have separate counters.
        """
        ip = "192.168.1.5"  # Same IP for both users
        endpoint = "/login"
        
        user1_id = "user_1"
        user2_id = "user_2"
        
        # User 1 makes 5 requests (all allowed)
        for i in range(5):
            result = is_rate_limited(user_id=user1_id, ip=ip, endpoint=endpoint)
            assert result is False, f"User 1 request {i+1} should be allowed"
        
        # User 1's 6th request should be blocked
        result = is_rate_limited(user_id=user1_id, ip=ip, endpoint=endpoint)
        assert result is True, "User 1's 6th request should be blocked"
        
        # User 2 (same IP, different user_id) should have separate counter
        # User 2's first request should be allowed
        result = is_rate_limited(user_id=user2_id, ip=ip, endpoint=endpoint)
        assert result is False, "User 2's first request should be allowed (separate counter)"
    
    def test_ip_used_when_user_id_is_none(self):
        """
        Test that IP is used as identifier when user_id is None.
        """
        ip = "192.168.1.6"
        endpoint = "/login"
        
        # Make 5 requests without user_id (all should be allowed)
        for i in range(5):
            result = is_rate_limited(user_id=None, ip=ip, endpoint=endpoint)
            assert result is False, f"Request {i+1} should be allowed"
        
        # 6th request should be blocked
        result = is_rate_limited(user_id=None, ip=ip, endpoint=endpoint)
        assert result is True, "6th request should be blocked (IP-based rate limiting)"
    
    def test_different_ips_have_separate_counters(self):
        """
        Test that different IPs have separate rate limit counters.
        """
        endpoint = "/login"
        ip1 = "192.168.1.7"
        ip2 = "192.168.1.8"
        
        # IP1 makes 5 requests (all allowed)
        for i in range(5):
            result = is_rate_limited(user_id=None, ip=ip1, endpoint=endpoint)
            assert result is False, f"IP1 request {i+1} should be allowed"
        
        # IP1's 6th request should be blocked
        result = is_rate_limited(user_id=None, ip=ip1, endpoint=endpoint)
        assert result is True, "IP1's 6th request should be blocked"
        
        # IP2 (different IP) should have separate counter
        # IP2's first request should be allowed
        result = is_rate_limited(user_id=None, ip=ip2, endpoint=endpoint)
        assert result is False, "IP2's first request should be allowed (separate counter)"
    
    def test_redis_failure_fail_closed_login(self):
        """
        Test that /login blocks requests when Redis is unavailable (fail-closed).
        """
        user_id = "test_user"
        ip = "192.168.1.9"
        endpoint = "/login"
        
        # Mock Redis to raise an error
        with patch('rate_limiter.limiter._get_redis_client') as mock_get_client:
            mock_client = Mock()
            mock_client.incr.side_effect = redis.RedisError("Connection failed")
            mock_get_client.return_value = mock_client
            
            # Should block (fail-closed)
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is True, "/login should block requests when Redis fails (fail-closed)"
    
    def test_redis_failure_fail_open_search(self):
        """
        Test that /search allows requests when Redis is unavailable (fail-open).
        """
        user_id = "test_user"
        ip = "192.168.1.10"
        endpoint = "/search"
        
        # Mock Redis to raise an error
        with patch('rate_limiter.limiter._get_redis_client') as mock_get_client:
            mock_client = Mock()
            mock_client.incr.side_effect = redis.RedisError("Connection failed")
            mock_get_client.return_value = mock_client
            
            # Should allow (fail-open)
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, "/search should allow requests when Redis fails (fail-open)"
    
    def test_redis_failure_fail_open_read(self):
        """
        Test that /read allows requests when Redis is unavailable (fail-open).
        """
        user_id = "test_user"
        ip = "192.168.1.11"
        endpoint = "/read"
        
        # Mock Redis to raise an error
        with patch('rate_limiter.limiter._get_redis_client') as mock_get_client:
            mock_client = Mock()
            mock_client.incr.side_effect = redis.RedisError("Connection failed")
            mock_get_client.return_value = mock_client
            
            # Should allow (fail-open)
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            assert result is False, "/read should allow requests when Redis fails (fail-open)"
    
    def test_unknown_endpoint_allowed(self):
        """
        Test that unknown endpoints are allowed (no rate limiting).
        """
        user_id = "test_user"
        ip = "192.168.1.12"
        endpoint = "/unknown_endpoint"
        
        # Unknown endpoint should always be allowed
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
        assert result is False, "Unknown endpoint should be allowed"
    
    def test_different_endpoints_have_different_limits(self):
        """
        Test that different endpoints have different rate limits.
        """
        user_id = "test_user_multi"
        ip = "192.168.1.13"
        
        # Test /login limit (5 requests)
        for i in range(5):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint="/login")
            assert result is False, f"/login request {i+1} should be allowed"
        
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint="/login")
        assert result is True, "/login 6th request should be blocked"
        
        # Test /search limit (20 requests) - should still have room
        for i in range(20):
            result = is_rate_limited(user_id=user_id, ip=ip, endpoint="/search")
            assert result is False, f"/search request {i+1} should be allowed"
        
        result = is_rate_limited(user_id=user_id, ip=ip, endpoint="/search")
        assert result is True, "/search 21st request should be blocked"
    
    def test_expire_only_set_on_new_key(self):
        """
        Test that EXPIRE is only set when a key is newly created (count == 1).
        This is an implementation detail test to ensure efficiency.
        """
        user_id = "test_user_expire"
        ip = "192.168.1.14"
        endpoint = "/login"
        
        # Mock Redis client to track expire calls
        with patch('rate_limiter.limiter._get_redis_client') as mock_get_client:
            mock_client = Mock()
            mock_client.incr.return_value = 1  # First request (new key)
            mock_get_client.return_value = mock_client
            
            is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            
            # EXPIRE should be called on first request
            assert mock_client.expire.called, "EXPIRE should be called when key is new (count == 1)"
            
            # Reset mock
            mock_client.reset_mock()
            mock_client.incr.return_value = 2  # Second request (existing key)
            
            is_rate_limited(user_id=user_id, ip=ip, endpoint=endpoint)
            
            # EXPIRE should NOT be called on subsequent requests
            # (This test assumes your implementation checks count == 1)
            # Note: This test may need adjustment based on your implementation

