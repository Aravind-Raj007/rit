from fastapi import FastAPI
from .db import init_db

app = FastAPI(title="CyberGuard Lite Python API", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": "cyberguard-lite-python"}
