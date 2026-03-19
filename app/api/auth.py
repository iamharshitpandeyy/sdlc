"""
Authentication API endpoints.

This module provides REST API endpoints for user authentication including
registration, login, logout, token refresh, and user profile retrieval.
"""

from datetime import datetime, timedelta
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.token import RefreshToken
from app.schemas.user import UserCreate, UserResponse, UserLogin
from app.schemas.token import Token, TokenRefresh, RefreshTokenRequest
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
)
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    responses={
        201: {"description": "User successfully created"},
        409: {"description": "Email already registered"},
        422: {"description": "Validation error (invalid email or weak password)"},
    },
)
def register(user_data: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    """
    Register a new user account.

    Creates a new user with the provided credentials. The password is securely
    hashed before storage.

    - **name**: User's display name (required, non-empty)
    - **email**: Valid email address (must be unique)
    - **password**: Password (minimum 8 characters)
    """
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    hashed_password = get_password_hash(user_data.password)
    user = User(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate user",
    responses={
        200: {"description": "Successfully authenticated, returns access and refresh tokens"},
        401: {"description": "Invalid credentials or inactive user"},
    },
)
def login(credentials: UserLogin, db: Session = Depends(get_db)) -> Token:
    """
    Authenticate a user and obtain access tokens.

    Validates user credentials and returns JWT access and refresh tokens
    for authenticated API access.

    - **email**: Registered email address
    - **password**: User's password

    Returns an access token (short-lived) and refresh token (long-lived).
    Use the access token in the Authorization header for protected endpoints.
    """
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive"
        )

    access_token = create_access_token(user.id)
    refresh_token_value = create_refresh_token()

    refresh_token = RefreshToken(
        user_id=user.id,
        token=refresh_token_value,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(refresh_token)
    db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token_value
    )


@router.post(
    "/refresh",
    response_model=TokenRefresh,
    summary="Refresh access token",
    responses={
        200: {"description": "Successfully refreshed, returns new access and refresh tokens"},
        401: {"description": "Invalid, expired, or revoked refresh token"},
    },
)
def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)) -> TokenRefresh:
    """
    Obtain a new access token using a refresh token.

    Use this endpoint when the access token has expired. The provided refresh
    token is revoked and a new token pair is issued.

    - **refresh_token**: Valid, non-expired refresh token from login or previous refresh

    Note: Each refresh token can only be used once. After use, it is revoked
    and a new refresh token is returned.
    """
    token_record = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.revoked == False
    ).first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    if token_record.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )

    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    token_record.revoked = True
    db.commit()

    new_refresh_token_value = create_refresh_token()
    new_refresh_token = RefreshToken(
        user_id=user.id,
        token=new_refresh_token_value,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_refresh_token)

    access_token = create_access_token(user.id)
    db.commit()

    return TokenRefresh(access_token=access_token, refresh_token=new_refresh_token_value)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    responses={
        200: {"description": "Current user's profile information"},
        401: {"description": "Not authenticated or invalid token"},
    },
)
def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    """
    Retrieve the current authenticated user's profile.

    Requires a valid access token in the Authorization header.

    Returns the user's profile information including ID, name, email,
    account status, and creation timestamp.
    """
    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout user",
    responses={
        200: {"description": "Successfully logged out"},
        401: {"description": "Not authenticated or invalid token"},
    },
)
def logout(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, str]:
    """
    Log out the current user by revoking their refresh token.

    Requires a valid access token in the Authorization header.

    - **refresh_token**: The refresh token to revoke

    After logout, the refresh token cannot be used to obtain new access tokens.
    The access token remains valid until it expires, but the user cannot
    refresh their session.
    """
    token_record = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.user_id == current_user.id,
        RefreshToken.revoked == False
    ).first()

    if token_record:
        token_record.revoked = True
        db.commit()

    return {"message": "Successfully logged out"}
