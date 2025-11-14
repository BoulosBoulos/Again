import os
import sys
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from reviews_service.main import app
from reviews_service.database import Base, engine

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


def test_user_can_create_and_list_room_reviews_publicly():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    body = {
        "room_id": 1,
        "rating": 4,
        "comment": " Nice room ",
    }

    res_create = client.post("/reviews", json=body, headers=headers)
    assert res_create.status_code == 201
    data = res_create.json()
    assert data["user_id"] == 1
    assert data["room_id"] == 1
    assert data["rating"] == 4
    # comment trimmed
    assert data["comment"] == "Nice room"

    # public list
    res_list = client.get("/reviews/room/1")
    assert res_list.status_code == 200
    items = res_list.json()
    assert len(items) == 1
    assert items[0]["comment"] == "Nice room"


def test_cannot_review_same_room_twice():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}
    body = {"room_id": 1, "rating": 5, "comment": "Great"}

    res1 = client.post("/reviews", json=body, headers=headers)
    assert res1.status_code == 201

    res2 = client.post("/reviews", json=body, headers=headers)
    assert res2.status_code == 400


def test_flag_and_hide_review():
    # user creates review
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    body = {"room_id": 1, "rating": 3, "comment": "OK"}

    res_create = client.post("/reviews", json=body, headers=headers_user)
    assert res_create.status_code == 201
    review_id = res_create.json()["id"]

    # another user flags it
    token_other = make_token(user_id=2, username="user2", role="regular")
    headers_other = {"Authorization": f"Bearer {token_other}"}

    res_flag = client.post(f"/reviews/{review_id}/flag", headers=headers_other)
    assert res_flag.status_code == 200
    assert res_flag.json()["is_flagged"] is True

    # moderator hides it
    token_mod = make_token(user_id=3, username="mod1", role="moderator")
    headers_mod = {"Authorization": f"Bearer {token_mod}"}

    res_hide = client.post(f"/reviews/{review_id}/hide", headers=headers_mod)
    assert res_hide.status_code == 200
    assert res_hide.json()["is_hidden"] is True

    # public list should not include hidden review
    res_public = client.get("/reviews/room/1")
    assert res_public.status_code == 200
    assert res_public.json() == []


def test_owner_can_update_and_delete_review():
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    body = {"room_id": 1, "rating": 2, "comment": "Bad"}

    res_create = client.post("/reviews", json=body, headers=headers_user)
    assert res_create.status_code == 201
    review_id = res_create.json()["id"]

    # update rating/comment
    update_body = {"rating": 4, "comment": "Actually good"}
    res_update = client.put(f"/reviews/{review_id}", json=update_body, headers=headers_user)
    assert res_update.status_code == 200
    updated = res_update.json()
    assert updated["rating"] == 4
    assert updated["comment"] == "Actually good"

    # delete
    res_delete = client.delete(f"/reviews/{review_id}", headers=headers_user)
    assert res_delete.status_code == 204

    # now public list should be empty
    res_public = client.get("/reviews/room/1")
    assert res_public.status_code == 200
    assert res_public.json() == []
