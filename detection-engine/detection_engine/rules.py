"""Detection rules that evaluate local lab log events for findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, LogEvent


BRUTE_FORCE_RULE_ID = "AUTH-BRUTE-FORCE-001"
SQLI_RULE_ID = "WEB-SQLI-PATTERN-001"
SEVERITY = "Medium"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=5)
SQLI_SIGNAL = "sql_injection_like_pattern"


def detect_all(events: list[LogEvent]) -> list[DetectionFinding]:
    """Run every implemented local lab detection rule."""

    findings = [
        *detect_brute_force(events),
        *detect_sqli_patterns(events),
    ]
    return sorted(findings, key=lambda finding: (finding.first_seen, finding.rule_id, finding.source_ip))


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
                rule_id=BRUTE_FORCE_RULE_ID,
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


def detect_sqli_patterns(events: list[LogEvent]) -> list[DetectionFinding]:
    """Detect SQLi-like suspicious input events from local lab telemetry."""

    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type != "suspicious_input":
            continue
        if event.raw.get("signal") != SQLI_SIGNAL:
            continue

        input_name = str(event.raw.get("input_name") or "unknown")
        request_path = str(event.raw.get("request_path") or "unknown")
        findings.append(
            DetectionFinding(
                rule_id=SQLI_RULE_ID,
                severity=SEVERITY,
                source_ip=event.source_ip,
                username=event.username,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                reason=(
                    f"SQL injection-like input signal {SQLI_SIGNAL!r} observed "
                    f"for field {input_name!r} on {request_path}"
                ),
            )
        )

    return sorted(findings, key=lambda finding: (finding.first_seen, finding.source_ip, finding.username))

