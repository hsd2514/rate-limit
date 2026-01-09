"""
Example Usage of Rate Limiter

This file shows how your rate limiter would be used in a real backend service.
You don't need to implement this - it's just for reference.
"""

from rate_limiter.limiter import is_rate_limited


def handle_login_request(user_id: str, ip: str):
    """
    Example: How a login endpoint would use the rate limiter
    """
    # Check rate limit
    if is_rate_limited(user_id=user_id, ip=ip, endpoint='/login'):
        return {
            'error': 'Too many requests. Please try again later.',
            'status_code': 429
        }
    
    # Proceed with login logic
    # ... your actual login code here ...
    return {'success': True}


def handle_search_request(user_id: str | None, ip: str, query: str):
    """
    Example: How a search endpoint would use the rate limiter
    """
    # Check rate limit (user_id might be None for anonymous users)
    if is_rate_limited(user_id=user_id, ip=ip, endpoint='/search'):
        return {
            'error': 'Rate limit exceeded',
            'status_code': 429
        }
    
    # Proceed with search logic
    # ... your actual search code here ...
    return {'results': []}


# Example usage scenarios:

# Scenario 1: Authenticated user
# user_id = "user_123"
# ip = "192.168.1.10"
# is_rate_limited(user_id=user_id, ip=ip, endpoint='/login')
# → Uses "rate:user:user_123:/login" as key

# Scenario 2: Anonymous user
# user_id = None
# ip = "192.168.1.10"
# is_rate_limited(user_id=None, ip=ip, endpoint='/search')
# → Uses "rate:ip:192.168.1.10:/search" as key

# Scenario 3: Multiple requests from same user
# Request 1: is_rate_limited("user_42", "1.2.3.4", "/login") → False (allowed)
# Request 2: is_rate_limited("user_42", "1.2.3.4", "/login") → False (allowed)
# ...
# Request 6: is_rate_limited("user_42", "1.2.3.4", "/login") → True (blocked!)

