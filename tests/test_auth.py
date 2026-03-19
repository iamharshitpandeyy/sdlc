import pytest
from datetime import datetime, timedelta
from unittest.mock import patch


class TestRegister:
    def test_register_success(self, client, test_user_data):
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == test_user_data["email"]
        assert data["name"] == test_user_data["name"]
        assert "id" in data
        assert "hashed_password" not in data
        assert "password" not in data

    def test_register_duplicate_email(self, client, test_user_data, registered_user):
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 409
        assert "Email already registered" in response.json()["detail"]

    def test_register_invalid_email(self, client):
        data = {
            "name": "Test User",
            "email": "invalid-email",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_weak_password(self, client):
        data = {
            "name": "Test User",
            "email": "test@example.com",
            "password": "short"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_empty_name(self, client):
        data = {
            "name": "",
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_whitespace_only_name(self, client):
        data = {
            "name": "   ",
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_missing_name(self, client):
        data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_missing_email(self, client):
        data = {
            "name": "Test User",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_missing_password(self, client):
        data = {
            "name": "Test User",
            "email": "test@example.com"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_register_empty_body(self, client):
        response = client.post("/api/auth/register", json={})
        assert response.status_code == 422

    def test_register_name_gets_trimmed(self, client):
        data = {
            "name": "  Test User  ",
            "email": "trimtest@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 201
        assert response.json()["name"] == "Test User"


class TestLogin:
    def test_login_success(self, client, test_user_data, registered_user):
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client, test_user_data, registered_user):
        login_data = {
            "email": test_user_data["email"],
            "password": "wrongpassword"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_login_nonexistent_user(self, client):
        login_data = {
            "email": "nonexistent@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_login_inactive_user(self, client, db_session, test_user_data, registered_user):
        from app.models.user import User
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        user.is_active = False
        db_session.commit()

        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401
        assert "User is inactive" in response.json()["detail"]

    def test_login_missing_email(self, client):
        login_data = {"password": "testpassword123"}
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 422

    def test_login_missing_password(self, client, registered_user, test_user_data):
        login_data = {"email": test_user_data["email"]}
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 422

    def test_login_empty_body(self, client):
        response = client.post("/api/auth/login", json={})
        assert response.status_code == 422

    def test_login_invalid_email_format(self, client):
        login_data = {
            "email": "invalid-email",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 422

    def test_login_empty_password(self, client, registered_user, test_user_data):
        login_data = {
            "email": test_user_data["email"],
            "password": ""
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401


class TestRefreshToken:
    def test_refresh_token_success(self, client, auth_tokens):
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_refresh_token_invalid(self, client):
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        assert response.status_code == 401
        assert "Invalid refresh token" in response.json()["detail"]

    def test_refresh_token_revoked(self, client, auth_tokens):
        client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 401

    def test_refresh_returns_new_refresh_token(self, client, auth_tokens):
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert "refresh_token" in data
        assert data["refresh_token"] != auth_tokens["refresh_token"]

    def test_continuous_refresh(self, client, auth_tokens):
        first_response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert first_response.status_code == 200
        first_data = first_response.json()

        second_response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": first_data["refresh_token"]}
        )
        assert second_response.status_code == 200
        second_data = second_response.json()
        assert "access_token" in second_data
        assert "refresh_token" in second_data

    def test_refresh_token_expired(self, client, db_session, auth_tokens):
        from app.models.token import RefreshToken
        token_record = db_session.query(RefreshToken).filter(
            RefreshToken.token == auth_tokens["refresh_token"]
        ).first()
        token_record.expires_at = datetime.utcnow() - timedelta(days=1)
        db_session.commit()

        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 401
        assert "Refresh token has expired" in response.json()["detail"]

    def test_refresh_token_inactive_user(self, client, db_session, auth_tokens, test_user_data):
        from app.models.user import User
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        user.is_active = False
        db_session.commit()

        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 401
        assert "User not found or inactive" in response.json()["detail"]

    def test_refresh_token_missing_field(self, client):
        response = client.post("/api/auth/refresh", json={})
        assert response.status_code == 422

    def test_refresh_token_empty_value(self, client):
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": ""}
        )
        assert response.status_code == 401


class TestGetMe:
    def test_get_me_success(self, client, auth_tokens, test_user_data):
        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user_data["email"]
        assert data["name"] == test_user_data["name"]
        assert "hashed_password" not in data

    def test_get_me_no_token(self, client):
        response = client.get("/api/auth/me")
        assert response.status_code == 403

    def test_get_me_invalid_token(self, client):
        response = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

    def test_get_me_expired_token(self, client, db_session, test_user_data, registered_user):
        from app.core.security import create_access_token
        from app.models.user import User
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        expired_token = create_access_token(user.id, expires_delta=timedelta(seconds=-1))

        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401

    def test_get_me_inactive_user(self, client, db_session, auth_tokens, test_user_data):
        from app.models.user import User
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        user.is_active = False
        db_session.commit()

        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 401
        assert "User is inactive" in response.json()["detail"]

    def test_get_me_deleted_user(self, client, db_session, auth_tokens, test_user_data):
        from app.models.user import User
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        db_session.delete(user)
        db_session.commit()

        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 401
        assert "User not found" in response.json()["detail"]

    def test_get_me_malformed_authorization_header(self, client):
        response = client.get(
            "/api/auth/me",
            headers={"Authorization": "InvalidFormat token123"}
        )
        assert response.status_code == 403


class TestLogout:
    def test_logout_success(self, client, auth_tokens):
        response = client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 200
        assert "Successfully logged out" in response.json()["message"]

    def test_logout_no_token(self, client, auth_tokens):
        response = client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 403

    def test_logout_invalid_refresh_token(self, client, auth_tokens):
        response = client.post(
            "/api/auth/logout",
            json={"refresh_token": "invalid_token"},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 200

    def test_logout_invalid_access_token(self, client, auth_tokens):
        response = client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]},
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

    def test_logout_already_revoked_token(self, client, auth_tokens):
        client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        response = client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 200
        assert "Successfully logged out" in response.json()["message"]

    def test_logout_missing_refresh_token_field(self, client, auth_tokens):
        response = client.post(
            "/api/auth/logout",
            json={},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        assert response.status_code == 422

    def test_logout_prevents_token_reuse(self, client, auth_tokens):
        client.post(
            "/api/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"}
        )
        response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        assert response.status_code == 401


class TestPasswordHashing:
    def test_password_not_stored_plaintext(self, client, db_session, test_user_data):
        from app.models.user import User
        client.post("/api/auth/register", json=test_user_data)
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        assert user is not None
        assert user.hashed_password != test_user_data["password"]
        assert user.hashed_password.startswith("$2b$")

    def test_same_password_different_hashes(self, client, db_session):
        from app.models.user import User
        user1_data = {
            "name": "User One",
            "email": "user1@example.com",
            "password": "samepassword123"
        }
        user2_data = {
            "name": "User Two",
            "email": "user2@example.com",
            "password": "samepassword123"
        }
        client.post("/api/auth/register", json=user1_data)
        client.post("/api/auth/register", json=user2_data)

        user1 = db_session.query(User).filter(User.email == user1_data["email"]).first()
        user2 = db_session.query(User).filter(User.email == user2_data["email"]).first()
        assert user1.hashed_password != user2.hashed_password


class TestAccessToken:
    def test_access_token_contains_user_id(self, auth_tokens):
        from app.core.security import decode_access_token
        payload = decode_access_token(auth_tokens["access_token"])
        assert payload is not None
        assert "sub" in payload
        assert payload["sub"] is not None

    def test_access_token_contains_type(self, auth_tokens):
        from app.core.security import decode_access_token
        payload = decode_access_token(auth_tokens["access_token"])
        assert payload is not None
        assert payload.get("type") == "access"

    def test_access_token_contains_expiration(self, auth_tokens):
        from app.core.security import decode_access_token
        payload = decode_access_token(auth_tokens["access_token"])
        assert payload is not None
        assert "exp" in payload

    def test_decode_invalid_token_returns_none(self):
        from app.core.security import decode_access_token
        result = decode_access_token("invalid_token")
        assert result is None

    def test_each_login_generates_unique_refresh_tokens(self, client, test_user_data, registered_user):
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        response1 = client.post("/api/auth/login", json=login_data)
        response2 = client.post("/api/auth/login", json=login_data)

        # Refresh tokens should always be unique (using secrets.token_urlsafe)
        assert response1.json()["refresh_token"] != response2.json()["refresh_token"]


class TestSecurityEdgeCases:
    def test_sql_injection_in_email(self, client):
        data = {
            "name": "Test",
            "email": "test@example.com'; DROP TABLE users;--",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 422

    def test_xss_in_name_field(self, client):
        data = {
            "name": "<script>alert('xss')</script>",
            "email": "xss@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 201
        assert response.json()["name"] == "<script>alert('xss')</script>"

    def test_very_long_name(self, client):
        data = {
            "name": "A" * 10000,
            "email": "longname@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code in [201, 422]

    def test_long_but_valid_password(self, client):
        # Test a reasonably long password that should be accepted
        data = {
            "name": "Test User",
            "email": "longpass@example.com",
            "password": "A" * 100  # 100 chars is well within bcrypt limits
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 201

    def test_unicode_in_name(self, client):
        data = {
            "name": "Tëst Üsér 中文 😀",
            "email": "unicode@example.com",
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=data)
        assert response.status_code == 201
        assert response.json()["name"] == "Tëst Üsér 中文 😀"

    def test_case_sensitivity_email(self, client, test_user_data, registered_user):
        uppercase_email_data = {
            "name": "Test User 2",
            "email": test_user_data["email"].upper(),
            "password": "testpassword123"
        }
        response = client.post("/api/auth/register", json=uppercase_email_data)
        assert response.status_code in [201, 409]


class TestMultipleTokens:
    def test_multiple_active_refresh_tokens(self, client, test_user_data, registered_user):
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        response1 = client.post("/api/auth/login", json=login_data)
        response2 = client.post("/api/auth/login", json=login_data)

        tokens1 = response1.json()
        tokens2 = response2.json()

        refresh_response1 = client.post(
            "/api/auth/refresh",
            json={"refresh_token": tokens1["refresh_token"]}
        )
        assert refresh_response1.status_code == 200

        refresh_response2 = client.post(
            "/api/auth/refresh",
            json={"refresh_token": tokens2["refresh_token"]}
        )
        assert refresh_response2.status_code == 200

    def test_logout_one_session_keeps_others_active(self, client, test_user_data, registered_user):
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        response1 = client.post("/api/auth/login", json=login_data)
        response2 = client.post("/api/auth/login", json=login_data)

        tokens1 = response1.json()
        tokens2 = response2.json()

        client.post(
            "/api/auth/logout",
            json={"refresh_token": tokens1["refresh_token"]},
            headers={"Authorization": f"Bearer {tokens1['access_token']}"}
        )

        refresh_response = client.post(
            "/api/auth/refresh",
            json={"refresh_token": tokens2["refresh_token"]}
        )
        assert refresh_response.status_code == 200
