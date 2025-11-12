from fastapi import FastAPI

app = FastAPI(title="Users Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "users", "status": "running"}
