from fastapi import FastAPI

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
