import os
from dotenv import load_dotenv
load_dotenv()


RATE_LIMITS = {
    '/login': (5, 60),
    '/search': (20, 60),
    '/read': (100, 60),
}

TIER_MULTIPLIERS = {
    'anonymous': 1,
    'free': 1,
    'pro': 5
}

FAILURE_BEHAVIOR = {
    '/login': 'fail-closed',   
    '/search': 'fail-open',    
    '/read': 'fail-open',     
}

PENALTY_STEP = 5
PENALTY_TTL_SECONDS = 60


REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.getenv('REDIS_PORT')
REDIS_DB = os.getenv('REDIS_DB')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

