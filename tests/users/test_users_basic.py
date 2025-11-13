import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from fastapi.testclient import TestClient

from users_service.main import app
from users_service.database import Base, engine
client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db():
    """
    Clean the users table before each test.
    We drop & recreate all tables for simplicity.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    # optional cleanup after each test
    Base.metadata.drop_all(bind=engine)


def register_user(username: str, email: str, role: str = "regular", password: str = "test1234"):
    payload = {
        "name": f"{username} Name",
        "username": username,
        "email": email,
        "role": role,
        "password": password,
    }
    response = client.post("/users/register", json=payload)
    assert response.status_code == 201
    return response.json()


def login_and_get_token(username: str, password: str):
    # login uses form data, not JSON
    data = {"username": username, "password": password}
    response = client.post("/users/login", data=data)
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    return body["access_token"]


def test_register_user_success():
    res = client.post(
        "/users/register",
        json={
            "name": "Admin User",
            "username": "admin1",
            "email": "admin1@example.com",
            "role": "admin",
            "password": "admin123",
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["username"] == "admin1"
    assert body["email"] == "admin1@example.com"
    assert body["role"] == "admin"
    # password should NOT be in the response
    assert "hashed_password" not in body
    assert "password" not in body


def test_register_duplicate_username_fails():
    register_user("user1", "user1@example.com")
    # same username, different email
    res = client.post(
        "/users/register",
        json={
            "name": "Other User",
            "username": "user1",
            "email": "other@example.com",
            "role": "regular",
            "password": "test1234",
        },
    )
    assert res.status_code == 400
    body = res.json()
    assert "exists" in body["detail"].lower()


def test_login_and_get_me():
    # create user then login
    register_user("user1", "user1@example.com", role="regular", password="user1234")
    token = login_and_get_token("user1", "user1234")

    # call /users/me with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/users/me", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "user1"
    assert body["email"] == "user1@example.com"
    assert body["role"] == "regular"


def test_regular_user_cannot_list_all_users():
    # regular user
    register_user("user1", "user1@example.com", role="regular", password="user1234")
    token = login_and_get_token("user1", "user1234")

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/users", headers=headers)
    assert res.status_code == 403


def test_admin_can_list_all_users():
    # create admin + regular
    register_user("admin1", "admin1@example.com", role="admin", password="admin123")
    register_user("user1", "user1@example.com", role="regular", password="user1234")

    token = login_and_get_token("admin1", "admin123")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/users", headers=headers)
    assert res.status_code == 200
    body = res.json()
    usernames = {u["username"] for u in body}
    assert "admin1" in usernames
    assert "user1" in usernames
