"""
main.py — FastAPI application entry point.
Run with:  uvicorn main:app --reload --port 8000
Docs at:   http://localhost:8000/docs
"""

from fastapi import FastAPI
from api.database import init_db
from api.routes import router

app = FastAPI(
    title="AbuseIPDB Local API",
    description="Local replacement for AbuseIPDB — for SOC portfolio use",
    version="1.0.0",
)

# Create tables on startup
@app.on_event("startup")
def startup():
    init_db()

app.include_router(router)

@app.get("/")
def root():
    return {"status": "ok", "message": "AbuseIPDB local API running"}