from fastapi import FastAPI
from .models import SecurityEvent
from .detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_multiple_sources,
)
from .storage import add_event, get_events

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
    add_event(event)

    event_history = get_events()

    alerts = []

    alerts.extend(detect_brute_force(event_history))
    alerts.extend(detect_success_after_failures(event_history))
    alerts.extend(detect_multiple_sources(event_history))

    return {
        "status": "accepted",
        "event": event,
        "alerts": alerts,
        "total_events": len(event_history),
    }


@app.get("/events")
def list_events():
    return {
        "total": len(get_events()),
        "events": get_events(),
    }
