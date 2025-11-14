import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from rooms_service.main import app
from rooms_service.database import Base, engine

# MUST MATCH users_service.auth AND rooms_service.auth
SECRET_KEY = "super-secret-smart-meeting-room-key"
ALGORITHM = "HS256"

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db():
    """
    Clean the rooms table before each test.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def make_token(username: str, role: str) -> str:
    """
    Create a JWT compatible with users_service + rooms_service.
    """
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
    # HTTPBearer returns 403 when missing credentials
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
    # create two rooms: one normal, one out_of_service
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

    # mark second room out_of_service via update
    update_payload = {"is_out_of_service": True}
    res_update = client.put(f"/rooms/{room_oos_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200
    assert res_update.json()["is_out_of_service"] is True

    # list rooms WITHOUT auth (public)
    res_list = client.get("/rooms")
    assert res_list.status_code == 200
    rooms = res_list.json()
    names = {r["name"] for r in rooms}

    assert "Room Active" in names
    assert "Room OOS" not in names  # excluded because out_of_service


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

    # delete (soft)
    res_delete = client.delete(f"/rooms/{room_id}", headers=headers)
    assert res_delete.status_code == 204

    # no longer retrievable
    res_get = client.get(f"/rooms/{room_id}")
    assert res_get.status_code == 404

    # and not listed in /rooms
    res_list = client.get("/rooms")
    assert res_list.status_code == 200
    rooms = res_list.json()
    ids = {r["id"] for r in rooms}
    assert room_id not in ids


def test_room_filters_by_capacity_location_and_equipment():
    token = make_token("admin1", "admin")
    headers = {"Authorization": f"Bearer {token}"}

    # small room, wrong equipment/location
    r1 = {
        "name": "Small Room",
        "capacity": 4,
        "equipment": "whiteboard",
        "location": "Building B",
    }
    # big room, matching filters
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

    # filter: min_capacity=10, location contains "Building A", equipment contains "projector"
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
