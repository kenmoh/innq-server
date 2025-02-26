import json
from fastapi import FastAPI, status, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.dependencies import TokenRefreshMiddleware, redis_client
from .routes import user_routes


app = FastAPI(title='InnQ', description='Hospitality Solutions')

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Specify your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TokenRefreshMiddleware)


@app.get('/', status_code=status.HTTP_200_OK)
def health_check() -> dict:
    try:
        # Check Redis connection
        redis_status = redis_client.ping()
        return {
            "status": "healthy",
            "redis": "connected" if redis_status else "error"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "redis": str(e)
        }


app.include_router(user_routes.user_router)
