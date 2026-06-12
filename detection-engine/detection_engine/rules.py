"""Detection rules that evaluate local lab log events for findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, LogEvent


BRUTE_FORCE_RULE_ID = "AUTH-BRUTE-FORCE-001"
SQLI_RULE_ID = "WEB-SQLI-PATTERN-001"
XSS_RULE_ID = "WEB-XSS-PATTERN-001"
BROKEN_ACCESS_RULE_ID = "BAC-PRIV-ESC-001"
SSRF_RULE_ID = "WEB-SSRF-INTERNAL-001"
SEVERITY = "Medium"
SEVERITY_HIGH = "High"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=5)
SQLI_SIGNAL = "sql_injection_like_pattern"
XSS_SIGNAL = "xss_like_pattern"
BROKEN_ACCESS_SIGNAL = "broken_access_control_pattern"
SSRF_SIGNAL = "ssrf_internal_target_pattern"


def detect_all(events: list[LogEvent]) -> list[DetectionFinding]:
    """Run every implemented local lab detection rule."""

    findings = [
        *detect_brute_force(events),
        *detect_sqli_patterns(events),
        *detect_xss_patterns(events),
        *detect_broken_access_control(events),
        *detect_ssrf_patterns(events),
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

    return _detect_suspicious_input_signal(
        events=events,
        rule_id=SQLI_RULE_ID,
        signal=SQLI_SIGNAL,
        label="SQL injection-like",
    )


def detect_xss_patterns(events: list[LogEvent]) -> list[DetectionFinding]:
    """Detect XSS-like suspicious input events from local lab telemetry."""

    return _detect_suspicious_input_signal(
        events=events,
        rule_id=XSS_RULE_ID,
        signal=XSS_SIGNAL,
        label="XSS-like",
    )


def _detect_suspicious_input_signal(
    *,
    events: list[LogEvent],
    rule_id: str,
    signal: str,
    label: str,
) -> list[DetectionFinding]:
    """Create one finding for each matching suspicious-input signal."""

    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type != "suspicious_input":
            continue
        if event.raw.get("signal") != signal:
            continue

        input_name = str(event.raw.get("input_name") or "unknown")
        request_path = str(event.raw.get("request_path") or "unknown")
        findings.append(
            DetectionFinding(
                rule_id=rule_id,
                severity=SEVERITY,
                source_ip=event.source_ip,
                username=event.username,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                reason=(
                    f"{label} input signal {signal!r} observed "
                    f"for field {input_name!r} on {request_path}"
                ),
            )
        )

    return sorted(findings, key=lambda finding: (finding.first_seen, finding.source_ip, finding.username))


def detect_ssrf_patterns(events: list[LogEvent]) -> list[DetectionFinding]:
    """Detect server-side fetches aimed at internal targets (SSRF).

    The vulnerable app logs an ``outbound_request`` event carrying the
    ``ssrf_internal_target_pattern`` signal whenever a server-side fetch is
    pointed at a loopback, private, link-local, or otherwise internal target
    (or uses a non-http(s) scheme). Each such event is an SSRF finding,
    regardless of whether the attempt was served or blocked.
    """

    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type != "outbound_request":
            continue
        if event.raw.get("signal") != SSRF_SIGNAL:
            continue

        request_path = str(event.raw.get("request_path") or "unknown")
        target = str(event.raw.get("target_host") or event.raw.get("target_url") or "unknown")
        findings.append(
            DetectionFinding(
                rule_id=SSRF_RULE_ID,
                severity=SEVERITY_HIGH,
                source_ip=event.source_ip,
                username=event.username,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                reason=(
                    f"Server-side request forgery: fetch on {request_path} aimed at "
                    f"internal target {target!r} from {event.source_ip}"
                ),
            )
        )

    return sorted(findings, key=lambda finding: (finding.first_seen, finding.source_ip, finding.username))


def detect_broken_access_control(events: list[LogEvent]) -> list[DetectionFinding]:
    """Detect admin-panel access granted via the broken access control exploit.

    The vulnerable app logs an ``admin_access`` event carrying the
    ``broken_access_control_pattern`` signal whenever a client-supplied role
    parameter (rather than a real admin session) is trusted to authorize the
    admin panel. Each such event is a privilege-escalation finding.
    """

    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type != "admin_access":
            continue
        if event.raw.get("signal") != BROKEN_ACCESS_SIGNAL:
            continue

        request_path = str(event.raw.get("request_path") or "unknown")
        findings.append(
            DetectionFinding(
                rule_id=BROKEN_ACCESS_RULE_ID,
                severity=SEVERITY_HIGH,
                source_ip=event.source_ip,
                username=event.username,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                reason=(
                    f"Privilege escalation: admin panel on {request_path} authorized via "
                    f"client-supplied role for {event.username!r} from {event.source_ip}"
                ),
            )
        )

    return sorted(findings, key=lambda finding: (finding.first_seen, finding.source_ip, finding.username))

