from fastapi import FastAPI
from app.models import SecurityEvent
from app.detector import analyze_event

app = FastAPI(
    title="SOC-NEXUS",
    description="Security Operations Center event detection API",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "name": "SOC-NEXUS",
        "status": "online",
        "description": "Security Operations Center event detection platform",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/events/analyze")
def analyze_security_event(event: SecurityEvent):
    result = analyze_event(event)

    return {
        "event": event,
        "analysis": result,
    }
