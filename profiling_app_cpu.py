import cProfile
from fastapi.testclient import TestClient

from users_service.main import app
from users_service.database import Base, engine

client = TestClient(app)


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def scenario_users():
    """
    Register and login many users to stress the users service.
    """
    for i in range(100):
        username = f"user{i}"
        email = f"user{i}@example.com"
        password = "User1234"

        # register user
        r = client.post(
            "/users/register",
            json={
                "name": f"User {i}",
                "username": username,
                "email": email,
                "password": password,
            },
        )

        # allow duplicate run (400 if already exists)
        if r.status_code not in (201, 400):
            raise RuntimeError(f"Unexpected status on register: {r.status_code}")

        # only login if this run actually created the user
        if r.status_code == 201:
            token_resp = client.post(
                "/users/login",
                data={"username": username, "password": password},
            )
            token_resp.raise_for_status()
            token = token_resp.json()["access_token"]

            headers = {"Authorization": f"Bearer {token}"}
            me_resp = client.get("/users/me", headers=headers)
            me_resp.raise_for_status()


def main():
    reset_db()
    scenario_users()


if __name__ == "__main__":
    # run cProfile and sort by cumulative time
    cProfile.run("main()", sort="cumtime")
