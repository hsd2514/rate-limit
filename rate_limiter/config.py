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

ENDPOINT_COST={
    '/login': 2,
    '/search': 5,
    '/read': 1,
}
PENALTY_STEP = 5
PENALTY_TTL_SECONDS = 60

DEFAULT_TRUST_SCORE = 1.0
TRUST_SCORE_MIN = 0.5
TRUST_SCORE_MAX = 1.5
TRUST_SCORE_INCREMENT = 0.01  
TRUST_SCORE_DECREMENT = 0.02  
TRUST_SCORE_TTL = 86400  
TRUST_SCORE_THRESHOLD = 0.5  #


REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.getenv('REDIS_PORT')
REDIS_DB = os.getenv('REDIS_DB')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

