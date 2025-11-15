import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from fastapi.testclient import TestClient
from jose import jwt
import httpx  

from rooms_service.main import app
from rooms_service.database import Base, engine

SECRET_KEY = "super-secret-smart-meeting-room-key"
ALGORITHM = "HS256"

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def make_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=15),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def test_create_room_requires_auth():
    payload = {
        "name": "Room A",
        "capacity": 10,
        "equipment": "projector",
        "location": "Building A",
    }
    res = client.post("/rooms", json=payload)
    assert res.status_code == 403


def test_regular_user_cannot_create_room():
    token = make_token("user1", "regular")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": "Room A",
        "capacity": 10,
        "equipment": "projector",
        "location": "Building A",
    }
    res = client.post("/rooms", json=payload, headers=headers)
    assert res.status_code == 403


def test_admin_can_create_room():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": "Conf A",
        "capacity": 10,
        "equipment": "projector,whiteboard",
        "location": "Building A - Floor 1",
    }
    res = client.post("/rooms", json=payload, headers=headers)
    assert res.status_code == 201
    body = res.json()
    assert body["name"] == "Conf A"
    assert body["capacity"] == 10
    assert body["is_active"] is True
    assert body["is_out_of_service"] is False


def test_list_rooms_is_public_and_excludes_out_of_service():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    r1 = {
        "name": "Room Active",
        "capacity": 5,
        "equipment": "projector",
        "location": "Building A",
    }
    r2 = {
        "name": "Room OOS",
        "capacity": 5,
        "equipment": "projector",
        "location": "Building A",
    }

    res1 = client.post("/rooms", json=r1, headers=headers)
    assert res1.status_code == 201

    res2 = client.post("/rooms", json=r2, headers=headers)
    assert res2.status_code == 201
    room_oos_id = res2.json()["id"]

    update_payload = {"is_out_of_service": True}
    res_update = client.put(f"/rooms/{room_oos_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200
    assert res_update.json()["is_out_of_service"] is True

    res_list = client.get("/rooms")
    assert res_list.status_code == 200
    rooms = res_list.json()
    names = {r["name"] for r in rooms}

    assert "Room Active" in names
    assert "Room OOS" not in names


def test_admin_can_delete_room_soft():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "Temp Room",
        "capacity": 5,
        "equipment": "projector",
        "location": "Building X",
    }
    res_create = client.post("/rooms", json=payload, headers=headers)
    assert res_create.status_code == 201
    room_id = res_create.json()["id"]

    res_delete = client.delete(f"/rooms/{room_id}", headers=headers)
    assert res_delete.status_code == 204

    res_get = client.get(f"/rooms/{room_id}")
    assert res_get.status_code == 404

    res_list = client.get("/rooms")
    assert res_list.status_code == 200
    rooms = res_list.json()
    ids = {r["id"] for r in rooms}
    assert room_id not in ids


def test_room_filters_by_capacity_location_and_equipment():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    r1 = {
        "name": "Small Room",
        "capacity": 4,
        "equipment": "whiteboard",
        "location": "Building B",
    }
    r2 = {
        "name": "Big Conf",
        "capacity": 20,
        "equipment": "projector,video",
        "location": "Building A - Floor 1",
    }

    res1 = client.post("/rooms", json=r1, headers=headers)
    assert res1.status_code == 201
    res2 = client.post("/rooms", json=r2, headers=headers)
    assert res2.status_code == 201

    res = client.get(
        "/rooms",
        params={
            "min_capacity": 10,
            "location": "Building A",
            "equipment_contains": "projector",
        },
    )
    assert res.status_code == 200
    rooms = res.json()
    names = {r["name"] for r in rooms}
    assert "Big Conf" in names
    assert "Small Room" not in names

def test_facility_manager_can_create_and_update_room():
    token = make_token("fm1", "facility_manager")
    headers = {"Authorization": f"Bearer {token}"}

    # create
    payload = {
        "name": "FM Room",
        "capacity": 8,
        "equipment": "whiteboard",
        "location": "Building C",
    }
    res_create = client.post("/rooms", json=payload, headers=headers)
    assert res_create.status_code == 201
    room = res_create.json()
    room_id = room["id"]

    # update
    update_payload = {"capacity": 12, "equipment": "whiteboard,projector"}
    res_update = client.put(f"/rooms/{room_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200
    updated = res_update.json()
    assert updated["capacity"] == 12
    assert "projector" in updated["equipment"]

def test_update_room_name_to_existing_one_fails():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    r1 = {
        "name": "Room1",
        "capacity": 5,
        "equipment": "projector",
        "location": "A",
    }
    r2 = {
        "name": "Room2",
        "capacity": 5,
        "equipment": "projector",
        "location": "A",
    }

    res1 = client.post("/rooms", json=r1, headers=headers)
    res2 = client.post("/rooms", json=r2, headers=headers)
    assert res1.status_code == 201
    assert res2.status_code == 201

    room2_id = res2.json()["id"]

    res_update = client.put(
        f"/rooms/{room2_id}",
        json={"name": "Room1"},
        headers=headers,
    )
    assert res_update.status_code == 400
    assert "exists" in res_update.json()["detail"].lower()

def test_room_status_available_and_out_of_service():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    # create normal room
    r1 = {
        "name": "Status Room",
        "capacity": 5,
        "equipment": "projector",
        "location": "Building A",
    }
    res_create = client.post("/rooms", json=r1, headers=headers)
    assert res_create.status_code == 201
    room = res_create.json()
    room_id = room["id"]

    # default status should be 'available'
    res_status = client.get(f"/rooms/{room_id}/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] == "available"

    # mark out_of_service
    res_update = client.put(
        f"/rooms/{room_id}",
        json={"is_out_of_service": True},
        headers=headers,
    )
    assert res_update.status_code == 200
    assert res_update.json()["is_out_of_service"] is True

    # now status should be 'out_of_service'
    res_status2 = client.get(f"/rooms/{room_id}/status")
    assert res_status2.status_code == 200
    assert res_status2.json()["status"] == "out_of_service"

def test_get_nonexistent_room_returns_404():
    res = client.get("/rooms/9999")
    assert res.status_code == 404

def test_room_status_uses_bookings_availability(monkeypatch):
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Create a room
    payload = {
        "name": "StatusRoom",
        "capacity": 5,
        "equipment": "projector",
        "location": "Building A",
    }
    res_create = client.post("/rooms", json=payload, headers=headers)
    assert res_create.status_code == 201
    room_id = res_create.json()["id"]

    # Fake Bookings /bookings/availability response
    class FakeResponse:
        def __init__(self, status_code, json_body):
            self.status_code = status_code
            self._json = json_body

        def json(self):
            return self._json

    def fake_httpx_get(url, params=None, timeout=None):
        # sanity check
        assert "/bookings/availability" in url
        assert params["room_id"] == room_id
        # pretend room is NOT available (booked)
        return FakeResponse(200, {"room_id": room_id, "available": False})

    monkeypatch.setattr(httpx, "get", fake_httpx_get)

    now = datetime.utcnow()
    res_status = client.get(
        f"/rooms/{room_id}/status",
        params={
            "start_time": (now + timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(hours=2)).isoformat(),
        },
    )
    assert res_status.status_code == 200
    body = res_status.json()
    assert body["room_id"] == room_id
    assert body["status"] == "booked"
