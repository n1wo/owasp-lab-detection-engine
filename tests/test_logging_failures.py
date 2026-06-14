"""Tests for the security logging & alerting failures scenario."""

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
from detection_engine.rules import detect_logging_failures  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "sensitive_action"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "admin"),
        raw=raw,
    )


# --- App behavior ----------------------------------------------------------


def test_insecure_role_change_is_unaudited(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/admin/role", data={"user": "test-user", "role": "admin"})

    assert response.status_code == 200
    assert b"no audit or alert record" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "sensitive_action"
    assert event["signal"] == "logging_failure_pattern"
    assert event["reason"] == "audit_logging_disabled"
    assert event["audit_logged"] is False
    assert event["alerted"] is False
    assert event["action"] == "role_change"
    assert event["target_user"] == "test-user"


def test_secure_role_change_is_audited(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/admin/role", data={"user": "test-user", "role": "admin"})

    assert response.status_code == 200
    assert b"audited and alerted" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "sensitive_action"
    assert event["signal"] is None
    assert event["reason"] == "audit_logged"
    assert event["audit_logged"] is True
    assert event["alerted"] is True


def test_role_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/admin/role")
    assert response.status_code == 200
    assert b"Admin role change" in response.data


def test_home_page_lists_logging_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"LOG-GAP-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_unaudited_action():
    event = make_event(
        {
            "event_type": "sensitive_action",
            "signal": "logging_failure_pattern",
            "action": "role_change",
            "target_user": "test-user",
            "request_path": "/admin/role",
        }
    )

    findings = detect_logging_failures([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "LOG-GAP-001"
    assert finding.severity == "High"
    assert "role_change" in finding.reason


def test_rule_ignores_audited_action():
    event = make_event(
        {
            "event_type": "sensitive_action",
            "signal": None,
            "action": "role_change",
            "target_user": "test-user",
        }
    )

    assert detect_logging_failures([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "logging_failure_pattern"})
    assert detect_logging_failures([event]) == []
