from datetime import datetime

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    username: str
    event_type: str
    status: str
    message: str


class SecurityAlert(BaseModel):
    rule_id: str
    severity: str
    title: str
    description: str
    source_ip: str | None = None
    username: str | None = None
    evidence_count: int = 0
