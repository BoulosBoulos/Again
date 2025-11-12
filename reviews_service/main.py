from fastapi import FastAPI

app = FastAPI(title="Reviews Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "reviews", "status": "running"}
