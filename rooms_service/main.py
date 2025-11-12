from fastapi import FastAPI

app = FastAPI(title="Rooms Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "rooms", "status": "running"}
