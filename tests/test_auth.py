import pytest


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


class TestPasswordHashing:
    def test_password_not_stored_plaintext(self, client, db_session, test_user_data):
        from app.models.user import User
        client.post("/api/auth/register", json=test_user_data)
        user = db_session.query(User).filter(User.email == test_user_data["email"]).first()
        assert user is not None
        assert user.hashed_password != test_user_data["password"]
        assert user.hashed_password.startswith("$2b$")
