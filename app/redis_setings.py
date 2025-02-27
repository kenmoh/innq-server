# Redis setup
import redis


REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set this in production
REDIS_PREFIX = "auth:"  # Prefix for Redis keys

# Redis client setup
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True,  # Return strings instead of bytes
)
