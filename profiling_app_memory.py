from memory_profiler import profile
from fastapi.testclient import TestClient

from users_service.main import app
from users_service.database import Base, engine

client = TestClient(app)


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def scenario_users():
    """
    Register many users to see memory usage of the flow.
    """
    for i in range(100):
        username = f"memuser{i}"
        email = f"memuser{i}@example.com"
        password = "User1234"

        r = client.post(
            "/users/register",
            json={
                "name": f"Mem User {i}",
                "username": username,
                "email": email,
                "password": password,
            },
        )

        if r.status_code not in (201, 400):
            raise RuntimeError(f"Unexpected status on register: {r.status_code}")


@profile
def run():
    reset_db()
    scenario_users()


if __name__ == "__main__":
    run()
