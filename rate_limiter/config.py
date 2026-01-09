import os
from dotenv import load_dotenv
load_dotenv()

"""
Rate Limiter Configuration

Define rate limits and failure behaviors for each endpoint.
"""

# Rate limits: {endpoint: (max_requests, window_seconds)}
RATE_LIMITS = {
    '/login': (5, 60),
    '/search': (20, 60),
    '/read': (100, 60),
}

# Failure behavior: {endpoint: 'fail-open' | 'fail-closed'}
FAILURE_BEHAVIOR = {
    '/login': 'fail-closed',   # Block on Redis failure
    '/search': 'fail-open',    # Allow on Redis failure
    '/read': 'fail-open',      # Allow on Redis failure
}

REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.getenv('REDIS_PORT')
REDIS_DB = os.getenv('REDIS_DB')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

