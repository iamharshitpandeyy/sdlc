"""
Security utilities for authentication.

This module provides functions for password hashing, verification,
and JWT token creation/validation.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.

    Args:
        plain_password: The plain text password to verify.
        hashed_password: The bcrypt hashed password to check against.

    Returns:
        True if the password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: The plain text password to hash.

    Returns:
        The bcrypt hashed password string.
    """
    return pwd_context.hash(password)


def create_access_token(user_id: UUID, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token for a user.

    Args:
        user_id: The unique identifier of the user.
        expires_delta: Optional custom expiration time. Defaults to
            ACCESS_TOKEN_EXPIRE_MINUTES from settings.

    Returns:
        Encoded JWT access token string.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access"
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token() -> str:
    """
    Create a cryptographically secure refresh token.

    Returns:
        A URL-safe random token string (32 bytes, base64 encoded).
    """
    return secrets.token_urlsafe(32)


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT access token.

    Args:
        token: The JWT token string to decode.

    Returns:
        The decoded token payload if valid, None otherwise.
        Returns None if the token is expired, malformed, or not
        an access token type.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None
