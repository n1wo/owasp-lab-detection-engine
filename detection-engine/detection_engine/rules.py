"""Detection rules that evaluate local lab log events for findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, LogEvent


RULE_ID = "AUTH-BRUTE-FORCE-001"
SEVERITY = "Medium"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def detect_brute_force(events: list[LogEvent]) -> list[DetectionFinding]:
    """Detect repeated local login failures by source IP and username."""

    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "login_failure":
            grouped[(event.source_ip, event.username)].append(event)

    findings: list[DetectionFinding] = []
    for (source_ip, username), failures in grouped.items():
        ordered = sorted(failures, key=lambda event: event.timestamp)
        finding = _first_threshold_window(source_ip, username, ordered)
        if finding is not None:
            findings.append(finding)

    return sorted(findings, key=lambda finding: (finding.first_seen, finding.source_ip, finding.username))


def _first_threshold_window(
    source_ip: str,
    username: str,
    failures: list[LogEvent],
) -> DetectionFinding | None:
    """Return the first failure window that crosses the brute-force threshold."""

    for start_index, first_event in enumerate(failures):
        window_events = [
            event
            for event in failures[start_index:]
            if event.timestamp - first_event.timestamp <= WINDOW
        ]
        if len(window_events) >= FAILURE_THRESHOLD:
            last_event = window_events[FAILURE_THRESHOLD - 1]
            return DetectionFinding(
                rule_id=RULE_ID,
                severity=SEVERITY,
                source_ip=source_ip,
                username=username,
                event_count=len(window_events),
                first_seen=first_event.timestamp,
                last_seen=last_event.timestamp,
                reason=(
                    f"{len(window_events)} login_failure events for user "
                    f"{username!r} from {source_ip} within 5 minutes"
                ),
            )
    return None

