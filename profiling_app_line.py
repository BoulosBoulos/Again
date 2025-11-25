from line_profiler import profile
from fastapi.testclient import TestClient

from users_service.main import app  # adjust import if needed

client = TestClient(app)


def register_and_login_user(username: str, email: str, password: str):
    # same logic you already have in profiling_app_cpu.py
    client.post("/users/register", json={
        "username": username,
        "email": email,
        "password": password,
    })
    res = client.post("/users/login", data={
        "username": username,
        "password": password,
    })
    print("LOGIN STATUS:", res.status_code, res.text)
    return res.json()["access_token"]


@profile
def scenario_users_line():
    # keep this small enough that output is readable
    for i in range(20):
        username = f"user{i}"
        email = f"user{i}@example.com"
        password = "User1234"
        token = register_and_login_user(username, email, password)
        # maybe one small booking call here if you want


if __name__ == "__main__":
    scenario_users_line()
