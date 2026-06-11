"""Tests for JSONL parsing and brute-force detection behavior."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DETECTION_ENGINE_ROOT = ROOT / "detection-engine"
sys.path.insert(0, str(DETECTION_ENGINE_ROOT))

from detection_engine.models import LogEvent  # noqa: E402
from detection_engine.parser import load_jsonl  # noqa: E402
from detection_engine.rules import detect_all, detect_brute_force, detect_sqli_patterns  # noqa: E402


def write_jsonl(path, records):
    """Write test records to a JSONL file, allowing raw malformed lines."""

    path.write_text(
        "\n".join(json.dumps(record) if isinstance(record, dict) else record for record in records),
        encoding="utf-8",
    )


def login_failure(source_ip="127.0.0.1", username="test-user", minute=0):
    """Build a valid login_failure record for parser and rule tests."""

    timestamp = datetime(2026, 6, 2, 9, minute, tzinfo=timezone.utc)
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event_type": "login_failure",
        "source_ip": source_ip,
        "username": username,
        "user_agent": "pytest-local",
        "request_path": "/login",
        "http_method": "POST",
        "status_code": 401,
        "lab_mode": "insecure",
        "reason": "invalid_credentials",
        "session_id": None,
    }


def event(event_type, source_ip="127.0.0.1", username="test-user", minute=0):
    """Build a normalized LogEvent directly for rule tests."""

    timestamp = datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        raw={},
    )


def suspicious_input_event(source_ip="127.0.0.1", minute=0):
    """Build a suspicious_input LogEvent for SQLi detection tests."""

    timestamp = datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return LogEvent(
        timestamp=timestamp,
        event_type="suspicious_input",
        source_ip=source_ip,
        username="anonymous",
        raw={
            "signal": "sql_injection_like_pattern",
            "input_name": "q",
            "request_path": "/search",
        },
    )


def test_parser_loads_valid_jsonl(tmp_path):
    """Verify that valid JSONL records become normalized log events."""

    log_file = tmp_path / "application.jsonl"
    write_jsonl(
        log_file,
        [
            login_failure(minute=0),
            {
                "timestamp": "2026-06-02T09:01:00Z",
                "event_type": "login_success",
                "source_ip": "127.0.0.1",
                "username": "test-user",
                "user_agent": "pytest-local",
                "request_path": "/login",
                "http_method": "POST",
                "status_code": 302,
                "lab_mode": "secure",
                "reason": "valid_credentials",
                "session_id": "fake-session-001",
            },
        ],
    )

    result = load_jsonl(log_file)

    assert result.errors == []
    assert len(result.events) == 2
    assert result.events[0].event_type == "login_failure"
    assert result.events[0].source_ip == "127.0.0.1"
    assert result.events[0].raw["request_path"] == "/login"


def test_parser_reports_invalid_jsonl_without_dropping_valid_events(tmp_path):
    """Verify malformed lines become errors while valid events remain usable."""

    log_file = tmp_path / "application.jsonl"
    write_jsonl(
        log_file,
        [
            login_failure(minute=0),
            "{not valid json",
            {"event_type": "login_failure", "source_ip": "127.0.0.1"},
        ],
    )

    result = load_jsonl(log_file)

    assert len(result.events) == 1
    assert len(result.errors) == 2
    assert result.errors[0].line_number == 2
    assert result.errors[1].line_number == 3


def test_parser_ignores_unknown_additional_fields(tmp_path):
    """Verify future extra fields are preserved but do not break parsing."""

    log_file = tmp_path / "application.jsonl"
    record = login_failure(minute=0)
    record["unexpected_future_field"] = "safe-local-value"
    write_jsonl(log_file, [record])

    result = load_jsonl(log_file)

    assert result.errors == []
    assert len(result.events) == 1
    assert result.events[0].event_type == "login_failure"
    assert result.events[0].raw["unexpected_future_field"] == "safe-local-value"


def test_brute_force_rule_triggers_on_five_failures_within_window():
    """Verify the brute-force rule fires at the documented threshold."""

    events = [event("login_failure", minute=minute) for minute in range(5)]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "AUTH-BRUTE-FORCE-001"
    assert finding.severity == "Medium"
    assert finding.source_ip == "127.0.0.1"
    assert finding.username == "test-user"
    assert finding.event_count == 5
    assert finding.first_seen == events[0].timestamp
    assert finding.last_seen == events[4].timestamp
    assert "5 login_failure events" in finding.reason


def test_brute_force_rule_does_not_trigger_on_fewer_failures():
    """Verify fewer than five matching failures produce no finding."""

    events = [event("login_failure", minute=minute) for minute in range(4)]

    assert detect_brute_force(events) == []


def test_brute_force_grouping_requires_same_source_ip_and_username():
    """Verify failures are grouped by both source IP and username."""

    events = [
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=0),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=1),
        event("login_failure", source_ip="127.0.0.1", username="other-user", minute=2),
        event("login_failure", source_ip="127.0.0.2", username="test-user", minute=3),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=4),
    ]

    assert detect_brute_force(events) == []


def test_brute_force_grouping_triggers_for_matching_group_only():
    """Verify only the source/user pair crossing the threshold is reported."""

    events = [
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=0),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=1),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=2),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=3),
        event("login_failure", source_ip="127.0.0.1", username="test-user", minute=4),
        event("login_failure", source_ip="127.0.0.2", username="test-user", minute=0),
        event("login_failure", source_ip="127.0.0.2", username="test-user", minute=1),
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0].source_ip == "127.0.0.1"
    assert findings[0].username == "test-user"


def test_sqli_rule_triggers_on_matching_suspicious_input_signal():
    """Verify SQLi-like suspicious-input telemetry creates a finding."""

    events = [suspicious_input_event()]

    findings = detect_sqli_patterns(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "WEB-SQLI-PATTERN-001"
    assert finding.severity == "Medium"
    assert finding.source_ip == "127.0.0.1"
    assert finding.username == "anonymous"
    assert finding.event_count == 1
    assert finding.first_seen == events[0].timestamp
    assert finding.last_seen == events[0].timestamp
    assert "sql_injection_like_pattern" in finding.reason
    assert "/search" in finding.reason


def test_sqli_rule_ignores_non_matching_suspicious_input_signal():
    """Verify unrelated suspicious-input signals do not trigger SQLi findings."""

    event = suspicious_input_event()
    event = LogEvent(
        timestamp=event.timestamp,
        event_type=event.event_type,
        source_ip=event.source_ip,
        username=event.username,
        raw={"signal": "xss_like_pattern", "input_name": "q", "request_path": "/search"},
    )

    assert detect_sqli_patterns([event]) == []


def test_detect_all_returns_brute_force_and_sqli_findings():
    """Verify the combined rule runner emits all implemented rule types."""

    events = [event("login_failure", minute=minute) for minute in range(5)]
    events.append(suspicious_input_event(minute=6))

    findings = detect_all(events)

    assert [finding.rule_id for finding in findings] == [
        "AUTH-BRUTE-FORCE-001",
        "WEB-SQLI-PATTERN-001",
    ]
