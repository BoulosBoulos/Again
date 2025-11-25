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


def test_create_review_success():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    body = {
        "room_id": 10,
        "rating": 4,
        "comment": "  Nice room with projector  ",
    }

    res = client.post("/api/v1/reviews", json=body, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["room_id"] == 10
    assert data["rating"] == 4
    # comment should be stripped
    assert data["comment"] == "Nice room with projector"
    assert data["user_id"] == 1
    assert data["is_hidden"] is False
    assert data["is_flagged"] is False


def test_duplicate_review_for_same_room_disallowed():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    body = {
        "room_id": 10,
        "rating": 5,
        "comment": "Great",
    }
    res1 = client.post("/api/v1/reviews", json=body, headers=headers)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/reviews", json=body, headers=headers)
    assert res2.status_code == 400
    assert "already reviewed" in res2.json()["detail"].lower()


def test_comment_cannot_be_empty_after_strip():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    body = {
        "room_id": 10,
        "rating": 3,
        "comment": "   ",  # whitespace only
    }
    res = client.post("/api/v1/reviews", json=body, headers=headers)
    # pydantic validation error
    assert res.status_code == 422


def test_public_room_reviews_hide_hidden_ones():
    # admin token
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    # two different users
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    body1 = {"room_id": 20, "rating": 5, "comment": "Visible review"}
    body2 = {"room_id": 20, "rating": 1, "comment": "Should be hidden"}

    r1 = client.post("/api/v1/reviews", json=body1, headers=headers_user1)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/reviews", json=body2, headers=headers_user2)
    assert r2.status_code == 201

    review2_id = r2.json()["id"]

    # admin hides second review
    res_hide = client.post(f"/api/v1/reviews/{review2_id}/hide", headers=headers_admin)
    assert res_hide.status_code == 200
    assert res_hide.json()["is_hidden"] is True

    # public endpoint should return only the visible one
    res_public = client.get("/api/v1/reviews/room/20")
    assert res_public.status_code == 200
    reviews = res_public.json()
    comments = {r["comment"] for r in reviews}
    assert "Visible review" in comments
    assert "Should be hidden" not in comments


def test_admin_moderator_auditor_can_list_all_reviews_with_filters():
    # create some reviews as regular user
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}

    for room_id in (1, 2):
        res = client.post(
            "/api/v1/reviews",
            json={"room_id": room_id, "rating": 4, "comment": f"Room {room_id}"},
            headers=headers_user,
        )
        assert res.status_code == 201

    # admin
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    res_all = client.get("/api/v1/reviews", headers=headers_admin)
    assert res_all.status_code == 200
    assert len(res_all.json()) >= 2

    # filter by room_id
    res_room1 = client.get("/api/v1/reviews", params={"room_id": 1}, headers=headers_admin)
    assert res_room1.status_code == 200
    for r in res_room1.json():
        assert r["room_id"] == 1

    # auditor can list too
    token_aud = make_token(user_id=50, username="aud1", role="auditor")
    headers_aud = {"Authorization": f"Bearer {token_aud}"}
    res_aud = client.get("/api/v1/reviews", headers=headers_aud)
    assert res_aud.status_code == 200


def test_owner_can_update_and_delete_review_but_others_cannot():
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    body = {"room_id": 42, "rating": 3, "comment": "Initial"}
    res = client.post("/api/v1/reviews", json=body, headers=headers_user1)
    assert res.status_code == 201
    review_id = res.json()["id"]

    # owner can update
    res_up = client.put(
        f"/api/v1/reviews/{review_id}",
        json={"rating": 5, "comment": "Updated"},
        headers=headers_user1,
    )
    assert res_up.status_code == 200
    assert res_up.json()["rating"] == 5
    assert res_up.json()["comment"] == "Updated"

    # another user cannot update/delete
    res_up_other = client.put(
        f"/api/v1/reviews/{review_id}",
        json={"rating": 1},
        headers=headers_user2,
    )
    assert res_up_other.status_code == 403

    res_del_other = client.delete(f"/api/v1/reviews/{review_id}", headers=headers_user2)
    assert res_del_other.status_code == 403

    # owner can delete
    res_del_owner = client.delete(f"/api/v1/reviews/{review_id}", headers=headers_user1)
    assert res_del_owner.status_code == 204


def test_auditor_and_service_account_cannot_write_reviews():
    token_aud = make_token(user_id=10, username="aud1", role="auditor")
    headers_aud = {"Authorization": f"Bearer {token_aud}"}

    token_svc = make_token(user_id=0, username="svc", role="service_account")
    headers_svc = {"Authorization": f"Bearer {token_svc}"}

    body = {"room_id": 1, "rating": 4, "comment": "Test"}

    # create
    res_aud_create = client.post("/api/v1/reviews", json=body, headers=headers_aud)
    res_svc_create = client.post("/api/v1/reviews", json=body, headers=headers_svc)
    assert res_aud_create.status_code == 403
    assert res_svc_create.status_code == 403


def test_flag_and_unflag_and_hide_cycle():
    token_user = make_token(user_id=1, username="user1", role="regular")
    token_mod = make_token(user_id=2, username="mod1", role="moderator")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    headers_mod = {"Authorization": f"Bearer {token_mod}"}

    # user creates review
    body = {"room_id": 5, "rating": 2, "comment": "Not great"}
    res = client.post("/api/v1/reviews", json=body, headers=headers_user)
    assert res.status_code == 201
    review_id = res.json()["id"]

    # user flags review
    res_flag = client.post(f"/api/v1/reviews/{review_id}/flag", headers=headers_user)
    assert res_flag.status_code == 200
    assert res_flag.json()["is_flagged"] is True

    # moderator hides it
    res_hide = client.post(f"/api/v1/reviews/{review_id}/hide", headers=headers_mod)
    assert res_hide.status_code == 200
    assert res_hide.json()["is_hidden"] is True

    # moderator can unflag
    res_unflag = client.post(f"/api/v1/reviews/{review_id}/unflag", headers=headers_mod)
    assert res_unflag.status_code == 200
    assert res_unflag.json()["is_flagged"] is False

    # moderator can unhide
    res_unhide = client.post(f"/api/v1/reviews/{review_id}/unhide", headers=headers_mod)
    assert res_unhide.status_code == 200
    assert res_unhide.json()["is_hidden"] is False


# ---------- EXTRA EDGE / RBAC TESTS ----------

def test_rating_out_of_range_fails():
    token = make_token(user_id=1, username="user1", role="regular")
    headers = {"Authorization": f"Bearer {token}"}

    # rating too low
    body_low = {"room_id": 1, "rating": 0, "comment": "Too low"}
    res_low = client.post("/api/v1/reviews", json=body_low, headers=headers)
    assert res_low.status_code == 422

    # rating too high
    body_high = {"room_id": 1, "rating": 6, "comment": "Too high"}
    res_high = client.post("/api/v1/reviews", json=body_high, headers=headers)
    assert res_high.status_code == 422


def test_moderator_cannot_create_review():
    token_mod = make_token(user_id=2, username="mod1", role="moderator")
    headers_mod = {"Authorization": f"Bearer {token_mod}"}

    body = {"room_id": 1, "rating": 4, "comment": "Mod cannot write"}
    res = client.post("/api/v1/reviews", json=body, headers=headers_mod)
    assert res.status_code == 403


def test_auditor_and_service_account_cannot_flag_reviews():
    # regular user creates a review
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    body = {"room_id": 1, "rating": 3, "comment": "Flag target"}
    res = client.post("/api/v1/reviews", json=body, headers=headers_user)
    assert res.status_code == 201
    review_id = res.json()["id"]

    token_aud = make_token(user_id=10, username="aud1", role="auditor")
    headers_aud = {"Authorization": f"Bearer {token_aud}"}
    token_svc = make_token(user_id=0, username="svc", role="service_account")
    headers_svc = {"Authorization": f"Bearer {token_svc}"}

    res_aud_flag = client.post(f"/api/v1/reviews/{review_id}/flag", headers=headers_aud)
    res_svc_flag = client.post(f"/api/v1/reviews/{review_id}/flag", headers=headers_svc)

    assert res_aud_flag.status_code == 403
    assert res_svc_flag.status_code == 403


def test_admin_can_update_and_delete_any_review():
    # user creates review
    token_user = make_token(user_id=1, username="user1", role="regular")
    headers_user = {"Authorization": f"Bearer {token_user}"}
    body = {"room_id": 99, "rating": 2, "comment": "To be moderated"}
    res = client.post("/api/v1/reviews", json=body, headers=headers_user)
    assert res.status_code == 201
    review_id = res.json()["id"]

    # admin updates and deletes it
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    res_update = client.put(
        f"/api/v1/reviews/{review_id}",
        json={"rating": 5, "comment": "Admin updated"},
        headers=headers_admin,
    )
    assert res_update.status_code == 200
    assert res_update.json()["rating"] == 5

    res_delete = client.delete(f"/api/v1/reviews/{review_id}", headers=headers_admin)
    assert res_delete.status_code == 204


def test_list_all_reviews_user_only_flagged_and_include_hidden_filters():
    # create two reviews with different users and flags
    token_user1 = make_token(user_id=1, username="user1", role="regular")
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    token_user2 = make_token(user_id=2, username="user2", role="regular")
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    r1 = client.post(
        "/api/v1/reviews",
        json={"room_id": 7, "rating": 4, "comment": "User1 review"},
        headers=headers_user1,
    )
    assert r1.status_code == 201
    r2 = client.post(
        "/api/v1/reviews",
        json={"room_id": 7, "rating": 1, "comment": "User2 flagged/hidden"},
        headers=headers_user2,
    )
    assert r2.status_code == 201
    review2_id = r2.json()["id"]

    # admin flags + hides second review
    token_admin = make_token(user_id=999, username="admin1", role="admin")
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    res_flag = client.post(f"/api/v1/reviews/{review2_id}/flag", headers=headers_admin)
    assert res_flag.status_code == 200

    res_hide = client.post(f"/api/v1/reviews/{review2_id}/hide", headers=headers_admin)
    assert res_hide.status_code == 200

    # user_id filter
    res_user1 = client.get(
        "/api/v1/reviews", params={"user_id": 1}, headers=headers_admin
    )
    assert res_user1.status_code == 200
    for rv in res_user1.json():
        assert rv["user_id"] == 1

    # only_flagged filter: should only return review2
    res_flagged = client.get(
        "/api/v1/reviews", params={"only_flagged": True}, headers=headers_admin
    )
    assert res_flagged.status_code == 200
    flagged = res_flagged.json()
    assert all(rv["is_flagged"] for rv in flagged)
    ids_flagged = {rv["id"] for rv in flagged}
    assert review2_id in ids_flagged

    # include_hidden=False: should exclude hidden reviews
    res_visible = client.get(
        "/api/v1/reviews", params={"include_hidden": False}, headers=headers_admin
    )
    assert res_visible.status_code == 200
    assert all(not rv["is_hidden"] for rv in res_visible.json())
