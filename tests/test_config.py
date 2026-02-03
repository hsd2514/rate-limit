"""
Test-specific configuration for rate limiter tests.

Uses SMALL limits for fast tests (fewer iterations needed).
"""

# Small limits = fewer iterations = fast tests
RATE_LIMITS = {
    '/login': (4, 2),      # 4 requests per 2s (cost=2 -> 2 allowed)
    '/search': (10, 2),    # 10 requests per 2s (cost=2 -> 5 allowed)
    '/read': (10, 2),      # 10 requests per 2s (cost=1 -> 10 allowed)
}

TIER_MULTIPLIERS = {
    'anonymous': 1,
    'free': 1,
    'pro': 3  # 3x for pro (smaller than prod for faster tests)
}

FAILURE_BEHAVIOR = {
    '/login': 'fail-closed',
    '/search': 'fail-open',
    '/read': 'fail-open',
}

ENDPOINT_COST = {
    '/login': 2,
    '/search': 2,  # Lower cost for faster tests
    '/read': 1,
}

PENALTY_STEP = 2  # Smaller step for tests
PENALTY_TTL_SECONDS = 2

DEFAULT_TRUST_SCORE = 1.0
TRUST_SCORE_MIN = 0.5
TRUST_SCORE_MAX = 1.5
TRUST_SCORE_INCREMENT = 0.0  # Disabled for predictable tests
TRUST_SCORE_DECREMENT = 0.0  # Disabled for predictable tests
TRUST_SCORE_TTL = 10
TRUST_SCORE_THRESHOLD = 0.5
