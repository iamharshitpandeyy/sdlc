"""
Token schemas for authentication request and response validation.

This module defines Pydantic models for JWT token-related API operations.
"""

from pydantic import BaseModel, Field


class Token(BaseModel):
    """
    Schema for login response containing access and refresh tokens.

    Returned after successful user authentication.
    """

    access_token: str = Field(
        ...,
        description="JWT access token for API authentication",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )
    refresh_token: str = Field(
        ...,
        description="Refresh token for obtaining new access tokens",
        examples=["dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."],
    )
    token_type: str = Field(
        default="bearer",
        description="Token type (always 'bearer')",
        examples=["bearer"],
    )


class TokenRefresh(BaseModel):
    """
    Schema for token refresh response.

    Returned after successfully refreshing tokens.
    """

    access_token: str = Field(
        ...,
        description="New JWT access token",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )
    refresh_token: str = Field(
        ...,
        description="New refresh token (old one is revoked)",
        examples=["bmV3IHJlZnJlc2ggdG9rZW4..."],
    )
    token_type: str = Field(
        default="bearer",
        description="Token type (always 'bearer')",
        examples=["bearer"],
    )


class RefreshTokenRequest(BaseModel):
    """
    Schema for token refresh and logout requests.

    Used when refreshing tokens or logging out.
    """

    refresh_token: str = Field(
        ...,
        description="The refresh token to use or revoke",
        examples=["dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."],
    )
