from typing import List

from .models import SecurityEvent


events: List[SecurityEvent] = []


def add_event(event: SecurityEvent) -> SecurityEvent:
    """Store a security event."""
    events.append(event)
    return event


def get_events() -> List[SecurityEvent]:
    """Return all stored security events."""
    return events


def clear_events() -> None:
    """Clear all stored events."""
    events.clear()
