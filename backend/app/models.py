from pydantic import BaseModel
from datetime import datetime


class SecurityEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    username: str
    event_type: str
    status: str
    message: str
