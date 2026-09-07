from fastapi import FastAPI
from .models import SecurityEvent

app = FastAPI(
    title="SOC-Nexus API",
    description="Security Operations Center platform for threat detection and incident response.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "name": "SOC-Nexus",
        "status": "online",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/events")
def ingest_event(event: SecurityEvent):
    return {
        "status": "accepted",
        "event": event,
    }
