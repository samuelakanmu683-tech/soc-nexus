from collections import defaultdict
from typing import List

from .models import SecurityEvent


BRUTE_FORCE_THRESHOLD = 5
SUCCESS_AFTER_FAILURE_THRESHOLD = 3


def detect_brute_force(events: List[SecurityEvent]) -> List[dict]:
    """Detect repeated failed authentication attempts from one source IP."""

    failures = defaultdict(list)

    for event in events:
        if event.status.lower() == "failed":
            failures[event.source_ip].append(event)

    alerts = []

    for source_ip, failed_events in failures.items():
        if len(failed_events) >= BRUTE_FORCE_THRESHOLD:
            alerts.append(
                {
                    "rule_id": "AUTH-001",
                    "severity": "HIGH",
                    "title": "SSH Brute Force",
                    "source_ip": source_ip,
                    "evidence_count": len(failed_events),
                    "description": (
                        f"{len(failed_events)} failed authentication attempts "
                        f"from {source_ip}"
                    ),
                }
            )

    return alerts


def detect_success_after_failures(events: List[SecurityEvent]) -> List[dict]:
    """Detect a successful authentication after repeated failures."""

    failures = defaultdict(int)
    alerts = []

    for event in events:
        key = (event.source_ip, event.username)

        if event.status.lower() == "failed":
            failures[key] += 1

        elif event.status.lower() == "success":
            if failures[key] >= SUCCESS_AFTER_FAILURE_THRESHOLD:
                alerts.append(
                    {
                        "rule_id": "AUTH-002",
                        "severity": "HIGH",
                        "title": "Successful Login Following Repeated Failures",
                        "source_ip": event.source_ip,
                        "username": event.username,
                        "evidence_count": failures[key] + 1,
                        "description": (
                            f"Successful login for {event.username} from "
                            f"{event.source_ip} followed "
                            f"{failures[key]} failed attempts"
                        ),
                    }
                )

    return alerts


def detect_multiple_sources(events: List[SecurityEvent]) -> List[dict]:
    """Detect multiple source IPs targeting the same account."""

    sources = defaultdict(set)

    for event in events:
        if event.status.lower() == "failed":
            sources[event.username].add(event.source_ip)

    alerts = []

    for username, source_ips in sources.items():
        if len(source_ips) >= 3:
            alerts.append(
                {
                    "rule_id": "AUTH-003",
                    "severity": "MEDIUM",
                    "title": "Multiple Sources Targeting Account",
                    "username": username,
                    "source_count": len(source_ips),
                    "description": (
                        f"{len(source_ips)} source IPs generated failed "
                        f"authentication events for {username}"
                    ),
                }
            )

    return alerts
