import os

# Redis setup
from cryptography.fernet import Fernet
from starlette.middleware.base import BaseHTTPMiddleware
import redis
import json
import time
from typing import Optional

from fastapi import Request, Response
from dotenv import load_dotenv

load_dotenv()
PG_ENCRYPTION_KEY = os.getenv("PG_ENCRYPTION_KEY")

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


# Store access and refresh tokens with user_id as the key
def store_tokens(
    user_id: str, access_token: str, refresh_token: str, expires_in: int
) -> None:
    # Store token data under user ID
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    token_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": int(time.time()) + expires_in,
    }
    redis_client.set(user_key, json.dumps(token_data))

    # Set expiration based on token lifetime + some buffer (e.g., 7 days)
    redis_client.expire(user_key, expires_in + (7 * 24 * 60 * 60))

    # Create lookup from access token to user ID
    token_key = f"{REDIS_PREFIX}token:{access_token}"
    redis_client.set(token_key, user_id)
    redis_client.expire(token_key, expires_in + (7 * 24 * 60 * 60))


# Get refresh token for a given access token


def get_refresh_token_for_user(access_token: str) -> Optional[str]:
    # Find user_id by access token
    token_key = f"{REDIS_PREFIX}token:{access_token}"
    user_id = redis_client.get(token_key)
    if not user_id:
        return None

    # Get the user's tokens
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    user_data = redis_client.get(user_key)
    if not user_data:
        return None

    try:
        token_data = json.loads(user_data)
        return token_data.get("refresh_token")
    except json.JSONDecodeError:
        return None


# Update tokens after refresh


def store_new_tokens(
    user_id: str, access_token: str, refresh_token: str, expires_in: int
) -> None:
    # Get existing user data to find old access token
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    user_data = redis_client.get(user_key)

    # Remove old access token lookup if it exists
    if user_data:
        try:
            old_tokens = json.loads(user_data)
            old_access_token = old_tokens.get("access_token")
            if old_access_token:
                old_token_key = f"{REDIS_PREFIX}token:{old_access_token}"
                redis_client.delete(old_token_key)
        except json.JSONDecodeError:
            pass

    # Store new tokens
    store_tokens(user_id, access_token, refresh_token, expires_in)


# Remove tokens on logout


def remove_tokens(user_id: str, access_token: str) -> None:
    # Remove token lookup
    token_key = f"{REDIS_PREFIX}token:{access_token}"
    redis_client.delete(token_key)

    # Remove user tokens
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    redis_client.delete(user_key)


# Token refresh middleware


class TokenRefreshMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Check if a new token was set during the request
        if hasattr(request.state, "new_access_token"):
            # Set the new token as a header
            response.headers["X-New-Access-Token"] = request.state.new_access_token

            # If the response is JSON, we could also include it in the response body
            if response.headers.get("content-type") == "application/json":
                try:
                    body = await response.body()
                    data = json.loads(body)
                    if isinstance(data, dict):
                        data["new_access_token"] = request.state.new_access_token
                        new_body = json.dumps(data).encode("utf-8")

                        # Create new response with updated body
                        new_response = Response(
                            content=new_body,
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            media_type=response.media_type,
                        )
                        return new_response
                except:
                    # If we can't modify the response body, just continue with the header approach
                    pass

        return response


# Store access and refresh tokens with user_id as the key
# def store_tokens(
#     user_id: str, access_token: str, refresh_token: str, expires_in: int
# ) -> None:
#     # Store token data under user ID
#     user_key = f"{REDIS_PREFIX}user:{user_id}"
#     token_data = {
#         "access_token": access_token,
#         "refresh_token": refresh_token,
#         "expires_at": int(time.time()) + expires_in,
#     }
#     redis_client.set(user_key, json.dumps(token_data))

#     # Set expiration based on token lifetime + some buffer (e.g., 7 days)
#     redis_client.expire(user_key, expires_in + (7 * 24 * 60 * 60))

#     # Create lookup from access token to user ID
#     token_key = f"{REDIS_PREFIX}token:{access_token}"
#     redis_client.set(token_key, user_id)
#     redis_client.expire(token_key, expires_in + (7 * 24 * 60 * 60))


# Get refresh token for a given access token


def get_refresh_token_for_user(access_token: str) -> Optional[str]:
    # Find user_id by access token
    token_key = f"{REDIS_PREFIX}token:{access_token}"
    user_id = redis_client.get(token_key)
    if not user_id:
        return None

    # Get the user's tokens
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    user_data = redis_client.get(user_key)
    if not user_data:
        return None

    try:
        token_data = json.loads(user_data)
        return token_data.get("refresh_token")
    except json.JSONDecodeError:
        return None


# Update tokens after refresh


def store_new_tokens(
    user_id: str, access_token: str, refresh_token: str, expires_in: int
) -> None:
    # Get existing user data to find old access token
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    user_data = redis_client.get(user_key)

    # Remove old access token lookup if it exists
    if user_data:
        try:
            old_tokens = json.loads(user_data)
            old_access_token = old_tokens.get("access_token")
            if old_access_token:
                old_token_key = f"{REDIS_PREFIX}token:{old_access_token}"
                redis_client.delete(old_token_key)
        except json.JSONDecodeError:
            pass

    # Store new tokens
    store_tokens(user_id, access_token, refresh_token, expires_in)


# Remove tokens on logout


def remove_tokens(user_id: str, access_token: str) -> None:
    # Remove token lookup
    token_key = f"{REDIS_PREFIX}token:{access_token}"
    redis_client.delete(token_key)

    # Remove user tokens
    user_key = f"{REDIS_PREFIX}user:{user_id}"
    redis_client.delete(user_key)


# @app.get("/users/me")
# async def read_users_me(current_user: dict = Depends(get_current_user)):
#     if not current_user:
#         raise HTTPException(status_code=401, detail="Not authenticated")
#     return current_user


def encrypt_data(data: str) -> str:
    f = Fernet(PG_ENCRYPTION_KEY)
    return f.encrypt(data.encode()).decode()


def decrypt_data(data: str) -> str:
    f = Fernet(PG_ENCRYPTION_KEY)
    return f.decrypt(data.encode()).decode()
