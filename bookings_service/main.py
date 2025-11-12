from fastapi import FastAPI

app = FastAPI(title="Bookings Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "bookings", "status": "running"}
