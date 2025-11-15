import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
import httpx
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
    # create bootstrap admin first
    register_user("admin1", "admin1@example.com", role="admin", password="admin123")

    # now this will be a true regular user
    register_user("user1", "user1@example.com", role="regular", password="user1234")
    token = login_and_get_token("user1", "user1234")

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/users/me", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "user1"
    assert body["email"] == "user1@example.com"
    assert body["role"] == "regular"


def test_regular_user_cannot_list_all_users():
    # bootstrap admin
    register_user("admin1", "admin1@example.com", role="admin", password="admin123")

    # second user → regular
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


def test_admin_can_reset_user_password():
    # create admin
    res_admin = client.post(
        "/users/register",
        json={
            "name": "Admin User",
            "username": "admin1",
            "email": "admin1@example.com",
            "role": "admin",
            "password": "admin123",
        },
    )
    assert res_admin.status_code == 201

    # create regular user
    res_user = client.post(
        "/users/register",
        json={
            "name": "Regular User",
            "username": "user1",
            "email": "user1@example.com",
            "role": "regular",
            "password": "oldpass123",
        },
    )
    assert res_user.status_code == 201
    user = res_user.json()
    user_id = user["id"]

    # admin logs in
    res_admin_login = client.post(
        "/users/login",
        data={"username": "admin1", "password": "admin123"},
    )
    assert res_admin_login.status_code == 200
    admin_token = res_admin_login.json()["access_token"]
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # admin resets user's password
    res_reset = client.post(
        f"/users/{user_id}/reset-password",
        json={"new_password": "newpass456"},
        headers=headers_admin,
    )
    assert res_reset.status_code == 204

    # old password should no longer work
    res_old_login = client.post(
        "/users/login",
        data={"username": "user1", "password": "oldpass123"},
    )
    assert res_old_login.status_code == 401

    # new password should work
    res_new_login = client.post(
        "/users/login",
        data={"username": "user1", "password": "newpass456"},
    )
    assert res_new_login.status_code == 200
    body = res_new_login.json()
    assert "access_token" in body

def test_register_duplicate_email_fails():
    # first user ok
    res1 = client.post(
        "/users/register",
        json={
            "name": "User One",
            "username": "user1",
            "email": "user@example.com",
            "role": "regular",
            "password": "User1234",
        },
    )
    assert res1.status_code == 201

    # second user with same email => 400
    res2 = client.post(
        "/users/register",
        json={
            "name": "User Two",
            "username": "user2",
            "email": "user@example.com",  # same email
            "role": "regular",
            "password": "User5678",
        },
    )
    assert res2.status_code == 400
    assert "email" in res2.json()["detail"].lower()

def test_update_my_profile_success():
    user = register_user("user1", "user1@example.com", role="regular", password="User1234")
    token = login_and_get_token("user1", "User1234")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.put(
        "/users/me",
        headers=headers,
        json={"name": "New Name", "email": "newemail@example.com"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "New Name"
    assert body["email"] == "newemail@example.com"

def test_update_email_to_existing_one_fails():
    # create two users
    u1 = register_user("user1", "user1@example.com", role="regular", password="User1234")
    u2 = register_user("user2", "user2@example.com", role="regular", password="User5678")

    token1 = login_and_get_token("user1", "User1234")
    headers1 = {"Authorization": f"Bearer {token1}"}

    # user1 tries to change email to user2's email
    res = client.put(
        "/users/me",
        headers=headers1,
        json={"email": "user2@example.com"},
    )
    assert res.status_code == 400
    assert "email" in res.json()["detail"].lower()

def test_delete_my_account():
    register_user("user1", "user1@example.com", role="regular", password="User1234")
    token = login_and_get_token("user1", "User1234")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.delete("/users/me", headers=headers)
    assert res.status_code == 204

    # token now points to a deleted user → should get 401
    res_me = client.get("/users/me", headers=headers)
    assert res_me.status_code == 401

def test_admin_can_delete_other_user():
    admin = register_user("admin1", "admin1@example.com", role="admin", password="Admin1234")
    user = register_user("user1", "user1@example.com", role="regular", password="User1234")

    admin_token = login_and_get_token("admin1", "Admin1234")
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    res = client.delete(f"/users/{user['id']}", headers=headers_admin)
    assert res.status_code == 204

    # user login should fail now
    res_login = client.post(
        "/users/login", data={"username": "user1", "password": "User1234"}
    )
    assert res_login.status_code == 401

def test_admin_can_change_user_role():
    admin = register_user("admin1", "admin1@example.com", role="admin", password="Admin1234")
    user = register_user("user1", "user1@example.com", role="regular", password="User1234")

    admin_token = login_and_get_token("admin1", "Admin1234")
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    res = client.put(
        f"/users/{user['id']}/role",
        headers=headers_admin,
        json={"role": "facility_manager"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["role"] == "facility_manager"

    # user logs in and sees updated role on /users/me
    user_token = login_and_get_token("user1", "User1234")
    headers_user = {"Authorization": f"Bearer {user_token}"}
    res_me = client.get("/users/me", headers=headers_user)
    assert res_me.status_code == 200
    assert res_me.json()["role"] == "facility_manager"

def test_auditor_read_only_on_users():
    # first user becomes admin
    admin = register_user("admin1", "admin1@example.com", role="admin", password="Admin1234")
    # second user starts as regular (backend forces it)
    auditor = register_user("aud1", "aud1@example.com", role="regular", password="Auditor123")

    # admin logs in
    admin_token = login_and_get_token("admin1", "Admin1234")
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # admin changes role of aud1 to auditor
    res_role = client.put(
        f"/users/{auditor['id']}/role",
        headers=headers_admin,
        json={"role": "auditor"},
    )
    assert res_role.status_code == 200
    assert res_role.json()["role"] == "auditor"

    # now login as auditor
    auditor_token = login_and_get_token("aud1", "Auditor123")
    headers_aud = {"Authorization": f"Bearer {auditor_token}"}

    # can list users (read-only)
    res_list = client.get("/users", headers=headers_aud)
    assert res_list.status_code == 200

    # cannot modify own profile
    res_update_me = client.put("/users/me", headers=headers_aud, json={"name": "Hack"})
    assert res_update_me.status_code == 403

    # cannot delete own account
    res_del_me = client.delete("/users/me", headers=headers_aud)
    assert res_del_me.status_code == 403


def test_regular_user_cannot_view_other_users_booking_history():
    # bootstrap admin so the second user is regular
    register_user("admin1", "admin1@example.com", role="admin", password="Admin1234")
    user1 = register_user("user1", "user1@example.com", role="regular", password="User1234")
    user2 = register_user("user2", "user2@example.com", role="regular", password="User5678")

    token_user1 = login_and_get_token("user1", "User1234")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}

    # user1 trying to view user2's booking history → should be forbidden
    res = client.get(f"/users/{user2['id']}/booking-history", headers=headers_user1)
    assert res.status_code == 403

def test_admin_can_view_user_booking_history_via_bookings_service(monkeypatch):
    # first user -> admin (bootstrap rule)
    admin = register_user("admin1", "admin1@example.com", role="admin", password="Admin1234")
    user = register_user("user1", "user1@example.com", role="regular", password="User1234")

    admin_token = login_and_get_token("admin1", "Admin1234")
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # fake bookings returned by the Bookings service
    fake_bookings = [
        {
            "id": 1,
            "user_id": user["id"],
            "room_id": 10,
            "start_time": "2025-01-01T09:00:00Z",
            "end_time": "2025-01-01T10:00:00Z",
            "status": "confirmed",
            "created_at": "2025-01-01T08:00:00Z",
        }
    ]

    class FakeResponse:
        def __init__(self, status_code, json_body):
            self.status_code = status_code
            self._json = json_body

        def json(self):
            return self._json

    def fake_httpx_get(url, params=None, headers=None, timeout=None):
        # basic sanity checks
        assert "/bookings" in url
        assert params is not None
        assert params.get("user_id") == user["id"]
        return FakeResponse(200, fake_bookings)

    # monkeypatch httpx.get used inside users_service
    monkeypatch.setattr(httpx, "get", fake_httpx_get)

    res = client.get(f"/users/{user['id']}/booking-history", headers=headers_admin)
    assert res.status_code == 200
    body = res.json()
    assert body["user_id"] == user["id"]
    assert body["bookings"] == fake_bookings
