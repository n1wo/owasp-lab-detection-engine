"""Tests for the fail-open exception-handling scenario."""

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
DETECTION_ENGINE_ROOT = ROOT / "detection-engine"
sys.path.insert(0, str(VULNERABLE_APP_ROOT))
sys.path.insert(0, str(DETECTION_ENGINE_ROOT))

from vulnerable_app import create_app  # noqa: E402
from detection_engine.models import LogEvent  # noqa: E402
from detection_engine.rules import detect_fail_open  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "exception_handling"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "anonymous"),
        raw=raw,
    )


def tampered_token():
    # Invalid base64 (contains '.' and '-'), so the entitlement check raises.
    return "premium.eyJwbGFuIjoicHJlbWl1bSJ9.t4mp3r-ed"


def valid_token(plan="premium"):
    return base64.b64encode(json.dumps({"plan": plan}).encode()).decode()


# --- App behavior ----------------------------------------------------------


def test_insecure_entitlement_fails_open_and_leaks_trace(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/entitlement", data={"token": tampered_token()})

    assert response.status_code == 200
    assert b"failed open" in response.data
    assert b"Leaked stack trace" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "exception_handling"
    assert event["signal"] == "fail_open_pattern"
    assert event["reason"] == "fail_open_on_exception"
    assert event["fail_open"] is True
    assert event["stack_trace_leaked"] is True
    assert event["granted"] is True
    assert event["success"] is True
    assert event["request_path"] == "/entitlement"


def test_secure_entitlement_fails_closed(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/entitlement", data={"token": tampered_token()})

    assert response.status_code == 403
    assert b"Access denied" in response.data
    assert b"Leaked stack trace" not in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "exception_handling"
    assert event["signal"] is None
    assert event["reason"] == "fail_closed_on_exception"
    assert event["fail_open"] is False
    assert event["granted"] is False
    assert event["success"] is False


def test_valid_premium_token_verifies_without_signal(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/entitlement", data={"token": valid_token("premium")})

    assert response.status_code == 200
    assert b"Premium entitlement verified" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "exception_handling"
    assert event["signal"] is None
    assert event["reason"] == "entitlement_verified"
    assert event["granted"] is True


def test_valid_free_token_does_not_grant_premium(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/entitlement", data={"token": valid_token("free")})

    assert response.status_code == 200
    assert b"premium access not granted" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["signal"] is None
    assert event["reason"] == "entitlement_verified"
    assert event["granted"] is False


def test_entitlement_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/entitlement")
    assert response.status_code == 200
    assert b"Entitlement check" in response.data
    assert b"FAIL-OPEN-001" in response.data


def test_home_page_lists_entitlement_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"FAIL-OPEN-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_fail_open_event():
    event = make_event(
        {
            "event_type": "exception_handling",
            "signal": "fail_open_pattern",
            "request_path": "/entitlement",
            "error_type": "Error",
            "stack_trace_leaked": True,
        }
    )

    findings = detect_fail_open([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "FAIL-OPEN-001"
    assert finding.severity == "High"
    assert "/entitlement" in finding.reason
    assert "stack trace" in finding.reason


def test_rule_ignores_fail_closed_event():
    event = make_event(
        {
            "event_type": "exception_handling",
            "signal": None,
            "request_path": "/entitlement",
        }
    )

    assert detect_fail_open([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "fail_open_pattern"})
    assert detect_fail_open([event]) == []
