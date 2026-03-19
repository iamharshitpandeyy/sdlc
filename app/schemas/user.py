"""
User schemas for request and response validation.

This module defines Pydantic models for user-related API operations.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    """
    Schema for user registration requests.

    Used when creating a new user account.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User's display name",
        examples=["John Doe"],
    )
    email: EmailStr = Field(
        ...,
        description="User's email address (must be unique)",
        examples=["john.doe@example.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        description="User's password (minimum 8 characters)",
        examples=["SecurePass123"],
    )

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserLogin(BaseModel):
    """
    Schema for user login requests.

    Used when authenticating a user.
    """

    email: EmailStr = Field(
        ...,
        description="Registered email address",
        examples=["john.doe@example.com"],
    )
    password: str = Field(
        ...,
        description="User's password",
        examples=["SecurePass123"],
    )


class UserResponse(BaseModel):
    """
    Schema for user profile responses.

    Returned when retrieving user information. Does not include sensitive
    data such as the password hash.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(
        ...,
        description="Unique user identifier",
    )
    name: str = Field(
        ...,
        description="User's display name",
    )
    email: str = Field(
        ...,
        description="User's email address",
    )
    is_active: bool = Field(
        ...,
        description="Whether the user account is active",
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when the user account was created",
    )
