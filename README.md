# Rate Limiter Exercise

Backend exercise: Build a rate limiter using Redis and Fixed Window Counter algorithm.

## Project Structure

```
rate-limit/
├── rate_limiter/
│   ├── __init__.py
│   ├── limiter.py          # Your core implementation here
│   └── config.py           # Rate limit configurations
├── tests/
│   └── test_limiter.py      # Your tests here
├── requirements.txt
├── TRADE_OFFS.md            # Document your decisions here
└── README.md
```

## Getting Started

1. Install dependencies: `pip install -r requirements.txt`
2. Make sure Redis is running locally (or configure connection)
3. Implement `is_rate_limited()` in `rate_limiter/limiter.py`
4. Run tests: `pytest` (tests are already written in `tests/test_limiter.py`)
5. Document trade-offs in `TRADE_OFFS.md`

## Core Function to Implement

```python
def is_rate_limited(user_id: str | None, ip: str, endpoint: str) -> bool:
    """
    Returns True if the request should be blocked.
    Returns False if the request is allowed.
    
    Rules:
    - Use user_id if present, otherwise use ip
    - Apply endpoint-specific limits
    - Use Redis atomic operations
    - Handle Redis failures according to endpoint rules
    """
```

## Rate Limits

| Endpoint  | Limit                     |
| --------- | ------------------------- |
| `/login`  | 5 requests / 60 seconds   |
| `/search` | 20 requests / 60 seconds  |
| `/read`   | 100 requests / 60 seconds |

## Failure Handling

| Endpoint  | Behavior                    |
| --------- | --------------------------- |
| `/login`  | Fail-closed (block request) |
| `/search` | Fail-open (allow request)   |
| `/read`   | Fail-open (allow request)   |

## Key Format

```
rate:{identifier}:{endpoint}
```

Examples:
- `rate:user:42:/login`
- `rate:ip:192.168.1.10:/search`

## Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test
pytest tests/test_limiter.py::TestRateLimiter::test_login_rate_limit_exceeds_limit
```

## Test Coverage

The test suite includes:
- ✅ Basic rate limiting (exceeding limits for all endpoints)
- ✅ Counter reset after window expiration
- ✅ User ID vs IP precedence
- ✅ Different IPs have separate counters
- ✅ Redis failure scenarios (fail-open and fail-closed)
- ✅ Unknown endpoint handling
- ✅ Different endpoints have different limits

**Note:** One test (`test_counter_resets_after_window`) takes 61 seconds to run as it waits for the window to expire.

## Redis Commands to Consider

- `INCR` - Atomic increment
- `EXPIRE` - Set expiration (only on new keys)
- `TTL` - Check time to live
- `GET` - Read current count

## Tips

1. Use Redis atomic operations (INCR) for counting
2. Set EXPIRE only when creating a new key
3. Check if key exists before setting EXPIRE
4. Handle Redis connection errors gracefully
5. Keep it simple - Fixed Window is intentionally basic

