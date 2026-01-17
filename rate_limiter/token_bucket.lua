-- Token Bucket Rate Limiter
-- KEYS[1]  -> rate limit key
-- ARGV[1]  -> capacity (max tokens)
-- ARGV[2]  -> refill_rate (tokens per second)
-- ARGV[3]  -> now (current unix timestamp in seconds)
-- ARGV[4]  -> cost (tokens per request, usually 1)

local key = KEYS[1]

local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

-- Read stored state
local data = redis.call("HMGET", key, "tokens", "last_refill")

local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])

-- Initialize bucket if key does not exist
if tokens == nil then
    tokens = capacity
    last_refill = now
end

-- Refill tokens based on time elapsed
local elapsed = math.max(0, now - last_refill)
local refill = elapsed * refill_rate
tokens = math.min(capacity, tokens + refill)

-- Decide allow / block
local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

-- Persist updated state
redis.call("HMSET", key,
    "tokens", tokens,
    "last_refill", now
)

-- Set TTL to avoid stale keys
redis.call("EXPIRE", key, math.ceil(capacity / refill_rate * 2))

return allowed
