"""Tests for the insecure checkout design scenario."""

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
from detection_engine.rules import detect_business_logic_abuse  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "business_action"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "test-user"),
        raw=raw,
    )


# --- App behavior ----------------------------------------------------------


def test_insecure_checkout_trusts_client_controlled_total(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/checkout",
        data={"quantity": "1", "client_total": "0.00"},
    )

    assert response.status_code == 200
    assert b"Client-controlled pricing was trusted" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "business_action"
    assert event["signal"] == "business_logic_abuse_pattern"
    assert event["reason"] == "trusted_client_controlled_total"
    assert event["success"] is True
    assert event["action"] == "checkout"
    assert event["expected_total"] == "49.00"
    assert event["allowed_minimum"] == "39.20"
    assert event["client_total"] == "0.00"


def test_secure_checkout_rejects_client_controlled_total(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/checkout",
        data={"quantity": "1", "client_total": "0.00"},
    )

    assert response.status_code == 400
    assert b"Checkout rejected" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "business_action"
    assert event["signal"] == "business_logic_abuse_pattern"
    assert event["reason"] == "rejected_client_controlled_total"
    assert event["success"] is False


def test_secure_checkout_accepts_server_valid_total(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/checkout",
        data={"quantity": "1", "client_total": "49.00"},
    )

    assert response.status_code == 200
    assert b"server-calculated limit" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "business_action"
    assert event["signal"] is None
    assert event["reason"] == "server_validated_checkout"
    assert event["success"] is True


def test_invalid_checkout_input_logs_failed_attempt(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/checkout",
        data={"quantity": "many", "client_total": "0.00"},
    )

    assert response.status_code == 400
    assert b"Quantity must be a whole number" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "business_action"
    assert event["signal"] is None
    assert event["reason"] == "invalid_checkout_input"
    assert event["success"] is False


def test_checkout_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/checkout")
    assert response.status_code == 200
    assert b"Checkout" in response.data
    assert b"DESIGN-LOGIC-001" in response.data


def test_home_page_lists_checkout_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"DESIGN-LOGIC-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_business_logic_abuse():
    event = make_event(
        {
            "event_type": "business_action",
            "signal": "business_logic_abuse_pattern",
            "action": "checkout",
            "request_path": "/checkout",
            "client_total": "0.00",
            "allowed_minimum": "39.20",
        }
    )

    findings = detect_business_logic_abuse([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DESIGN-LOGIC-001"
    assert finding.severity == "High"
    assert "0.00" in finding.reason
    assert "/checkout" in finding.reason


def test_rule_ignores_valid_checkout():
    event = make_event(
        {
            "event_type": "business_action",
            "signal": None,
            "action": "checkout",
        }
    )

    assert detect_business_logic_abuse([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "business_logic_abuse_pattern"})
    assert detect_business_logic_abuse([event]) == []
