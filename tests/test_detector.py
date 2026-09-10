from datetime import datetime

from backend.app.detector import (
    analyze_events,
    detect_brute_force,
    detect_multiple_sources,
    detect_success_after_failures,
)
from backend.app.models import SecurityEvent


def create_event(
    source_ip: str,
    username: str,
    status: str,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(),
        source_ip=source_ip,
        username=username,
        event_type="SSH_LOGIN",
        status=status,
        message=f"{status} SSH authentication",
    )


def test_detect_brute_force():
    events = [
        create_event("203.0.113.50", "admin", "failed")
        for _ in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-001"
    assert alerts[0]["severity"] == "HIGH"


def test_detect_success_after_failures():
    events = [
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "success"),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-002"
    assert alerts[0]["severity"] == "HIGH"


def test_detect_multiple_sources():
    events = [
        create_event("198.51.100.20", "administrator", "failed"),
        create_event("198.51.100.21", "administrator", "failed"),
        create_event("198.51.100.22", "administrator", "failed"),
    ]

    alerts = detect_multiple_sources(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-003"
    assert alerts[0]["severity"] == "MEDIUM"
def test_analyze_events():
    events = [
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
        create_event("203.0.113.50", "admin", "failed"),
    ]

    alerts = analyze_events(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-001"
