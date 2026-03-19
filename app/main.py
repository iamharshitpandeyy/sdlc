"""
User Authentication API

A FastAPI-based REST API providing secure user authentication with JWT tokens.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.database import engine, Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.

    Creates database tables on startup and handles cleanup on shutdown.
    """
    Base.metadata.create_all(bind=engine)
    yield


API_DESCRIPTION = """
## User Authentication API

A secure REST API for user authentication using JWT (JSON Web Tokens).

### Features

* **User Registration** - Create new user accounts with email and password
* **User Login** - Authenticate users and receive access/refresh tokens
* **Token Refresh** - Obtain new access tokens using refresh tokens
* **User Profile** - Retrieve current user information
* **Logout** - Revoke refresh tokens to end sessions

### Authentication

This API uses **Bearer Token** authentication. After logging in, include the
access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Token Lifecycle

* **Access Token**: Short-lived token for API access (expires in minutes)
* **Refresh Token**: Long-lived token for obtaining new access tokens (expires in days)

When the access token expires, use the refresh endpoint to obtain a new one
without requiring the user to log in again.
"""

TAGS_METADATA = [
    {
        "name": "auth",
        "description": "Authentication operations including registration, login, logout, and token management.",
    },
]

app = FastAPI(
    lifespan=lifespan,
    title="User Authentication API",
    description=API_DESCRIPTION,
    version="1.0.0",
    openapi_tags=TAGS_METADATA,
    contact={
        "name": "API Support",
    },
    license_info={
        "name": "MIT",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)


@app.get("/", tags=["root"], summary="API Root", include_in_schema=False)
def root():
    """
    Root endpoint providing API information and documentation links.

    Returns:
        dict: API welcome message with links to documentation.
    """
    return {"message": "User Authentication API", "docs": "/docs", "redoc": "/redoc"}
