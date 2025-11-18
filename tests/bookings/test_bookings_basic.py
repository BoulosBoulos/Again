import os
import sys
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from bookings_service.main import app
from bookings_service.database import Base, engine

SECRET_KEY = "super-secret-smart-meeting-room-key"
ALGORITHM = "HS256"

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def make_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def test_regular_user_can_create_booking():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }

    res = client.post("/bookings", json=body, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["user_id"] == 1
    assert data["room_id"] == 1
    assert data["status"] == "confirmed"


def test_cannot_create_overlapping_booking():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    body1 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    body2 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1, minutes=30)).isoformat(),
        "end_time": (now + timedelta(hours=2, minutes=30)).isoformat(),
    }

    res1 = client.post("/bookings", json=body1, headers=headers)
    assert res1.status_code == 201

    res2 = client.post("/bookings", json=body2, headers=headers)
    assert res2.status_code == 400
    assert "already booked" in res2.json()["detail"].lower()


def test_list_my_bookings_filters_by_user():
    # user1 creates booking in room 1
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}

    now = datetime.now(timezone.utc)
    body_user1 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res1 = client.post("/bookings", json=body_user1, headers=headers_user1)
    assert res1.status_code == 201

    # user2 creates booking in a DIFFERENT room (no conflict)
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}
    body_user2 = {
        "room_id": 2,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res2 = client.post("/bookings", json=body_user2, headers=headers_user2)
    assert res2.status_code == 201

    # user1 lists "my" bookings → should only see their own
    res_me = client.get("/bookings/me", headers=headers_user1)
    assert res_me.status_code == 200
    bookings_me = res_me.json()
    assert all(b["user_id"] == 1 for b in bookings_me)
    assert len(bookings_me) == 1


def test_admin_can_list_all_bookings():
    now = datetime.now(timezone.utc)

    # user1 booking
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    body1 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res1 = client.post("/bookings", json=body1, headers=headers_user1)
    assert res1.status_code == 201

    # user2 booking later (no overlap)
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}
    body2 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=3)).isoformat(),
        "end_time": (now + timedelta(hours=4)).isoformat(),
    }
    res2 = client.post("/bookings", json=body2, headers=headers_user2)
    assert res2.status_code == 201

    # admin lists all bookings
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    res = client.get("/bookings", headers=headers_admin)
    assert res.status_code == 200
    all_bookings = res.json()
    assert len(all_bookings) >= 2


def test_owner_can_cancel_own_booking():
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}

    now = datetime.now(timezone.utc)
    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res_create = client.post("/bookings", json=body, headers=headers_user1)
    assert res_create.status_code == 201
    booking_id = res_create.json()["id"]

    res_delete = client.delete(f"/bookings/{booking_id}", headers=headers_user1)
    assert res_delete.status_code == 204

    # overlapping booking should now be allowed (since previous is cancelled)
    res_new = client.post("/bookings", json=body, headers=headers_user1)
    assert res_new.status_code == 201


def test_update_booking_enforces_conflicts():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)

    # booking1: 09:00–10:00
    body1 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res1 = client.post("/bookings", json=body1, headers=headers)
    assert res1.status_code == 201
    booking1 = res1.json()

    # booking2: 11:00–12:00 (no overlap)
    body2 = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=3)).isoformat(),
        "end_time": (now + timedelta(hours=4)).isoformat(),
    }
    res2 = client.post("/bookings", json=body2, headers=headers)
    assert res2.status_code == 201
    booking2 = res2.json()

    # try to update booking2 to overlap booking1 (should fail)
    update_body = {
        "start_time": (now + timedelta(hours=1, minutes=30)).isoformat(),
        "end_time": (now + timedelta(hours=2, minutes=30)).isoformat(),
    }
    res_update = client.put(f"/bookings/{booking2['id']}", json=update_body, headers=headers)
    assert res_update.status_code == 400
    assert "already booked" in res_update.json()["detail"].lower()


def test_check_availability_endpoint():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    booking_body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    # create a booking to block the slot
    res = client.post("/bookings", json=booking_body, headers=headers)
    assert res.status_code == 201

    # check overlapping interval -> not available
    res_busy = client.get(
        "/bookings/availability",
        params={
            "room_id": 1,
            "start_time": (now + timedelta(hours=1, minutes=30)).isoformat(),
            "end_time": (now + timedelta(hours=1, minutes=45)).isoformat(),
        },
        headers=headers,   # <-- availability requires auth
    )
    assert res_busy.status_code == 200
    busy_info = res_busy.json()
    assert busy_info["room_id"] == 1
    assert busy_info["available"] is False

    # check non-overlapping interval -> available
    res_free = client.get(
        "/bookings/availability",
        params={
            "room_id": 1,
            "start_time": (now + timedelta(hours=3)).isoformat(),
            "end_time": (now + timedelta(hours=4)).isoformat(),
        },
        headers=headers,   # <-- availability requires auth
    )
    assert res_free.status_code == 200
    free_info = res_free.json()
    assert free_info["available"] is True


def test_availability_requires_auth_and_moderator_forbidden():
    now = datetime.now(timezone.utc)

    params = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }

    # no token → 403 (HTTPBearer)
    res_no_auth = client.get("/bookings/availability", params=params)
    assert res_no_auth.status_code == 403

    # moderator role is NOT in availability_roles → 403
    mod_token = make_token(user_id=3, username="mod1", role="moderator")
    headers_mod = {"Authorization": f"Bearer {mod_token}"}
    res_mod = client.get("/bookings/availability", params=params, headers=headers_mod)
    assert res_mod.status_code == 403


def test_availability_invalid_time_range_returns_400():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    # end <= start
    res = client.get(
        "/bookings/availability",
        params={
            "room_id": 1,
            "start_time": (now + timedelta(hours=2)).isoformat(),
            "end_time": (now + timedelta(hours=1)).isoformat(),
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "end_time must be after start_time" in res.json()["detail"]


def test_auditor_cannot_create_or_modify_bookings():
    token_aud = make_token(user_id=10, username="aud1", role="auditor")
    headers_aud = {"Authorization": f"Bearer {token_aud}"}

    now = datetime.now(timezone.utc)
    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }

    # cannot create
    res_create = client.post("/bookings", json=body, headers=headers_aud)
    assert res_create.status_code == 403

    # prepare a booking with a regular user
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    res = client.post("/bookings", json=body, headers=headers_user)
    assert res.status_code == 201
    booking_id = res.json()["id"]

    # auditor cannot update
    res_update = client.put(f"/bookings/{booking_id}", json={"room_id": 2}, headers=headers_aud)
    assert res_update.status_code == 403

    # auditor cannot cancel
    res_delete = client.delete(f"/bookings/{booking_id}", headers=headers_aud)
    assert res_delete.status_code == 403


def test_regular_user_cannot_modify_others_booking():
    now = datetime.now(timezone.utc)

    # user1 creates booking
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res_create = client.post("/bookings", json=body, headers=headers_user1)
    assert res_create.status_code == 201
    booking_id = res_create.json()["id"]

    # user2 tries to update/cancel user1's booking
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    res_update = client.put(
        f"/bookings/{booking_id}",
        json={"room_id": 2},
        headers=headers_user2,
    )
    assert res_update.status_code == 403

    res_delete = client.delete(f"/bookings/{booking_id}", headers=headers_user2)
    assert res_delete.status_code == 403


def test_admin_can_update_booking_status():
    now = datetime.now(timezone.utc)

    # user booking
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=2)).isoformat(),
    }
    res_create = client.post("/bookings", json=body, headers=headers_user)
    assert res_create.status_code == 201
    booking_id = res_create.json()["id"]

    # admin updates status to cancelled without delete
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    res_update = client.put(
        f"/bookings/{booking_id}",
        json={"status": "cancelled"},
        headers=headers_admin,
    )
    assert res_update.status_code == 200
    assert res_update.json()["status"] == "cancelled"


def test_create_booking_with_invalid_time_fails():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}
    now = datetime.now(timezone.utc)

    body = {
        "room_id": 1,
        "start_time": (now + timedelta(hours=2)).isoformat(),
        "end_time": (now + timedelta(hours=1)).isoformat(),  # end < start
    }
    res = client.post("/bookings", json=body, headers=headers)
    assert res.status_code == 400
    assert "end_time must be after start_time" in res.json()["detail"]
