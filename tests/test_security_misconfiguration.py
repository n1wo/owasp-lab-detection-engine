"""Tests for the security misconfiguration debug-endpoint scenario."""

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
from detection_engine.rules import detect_config_exposure  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "config_exposure"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "anonymous"),
        raw=raw,
    )


# --- App behavior ----------------------------------------------------------


def test_debug_endpoint_exposes_config_in_insecure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get("/debug")

    assert response.status_code == 200
    body = response.data.decode()
    assert "Application configuration" in body
    # The signing secret key is the headline disclosure.
    assert "local-lab-dev-key" in body
    assert "secret_key" in body

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "config_exposure"
    assert event["signal"] == "config_exposure_pattern"
    assert event["reason"] == "exposed_debug_config"
    assert event["success"] is True
    assert "secret_key" in event["exposed_keys"]


def test_debug_endpoint_disabled_in_secure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get("/debug")

    assert response.status_code == 404
    body = response.data.decode()
    assert "disabled in secure mode" in body
    assert "local-lab-dev-key" not in body

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "config_exposure"
    assert event["signal"] is None
    assert event["reason"] == "debug_endpoint_disabled"
    assert event["success"] is False
    assert event["exposed_keys"] == []


def test_debug_endpoint_uses_runtime_mode_after_toggle(tmp_path):
    # Start insecure, toggle to secure, and confirm the endpoint disables live.
    client = make_app(tmp_path, mode="insecure").test_client()
    assert client.get("/debug").status_code == 200

    client.post("/lab/mode", data={"next": "/debug"})

    assert client.get("/debug").status_code == 404


def test_home_page_lists_misconfiguration_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"CONFIG-EXPOSURE-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_exposed_config_event():
    event = make_event(
        {
            "event_type": "config_exposure",
            "request_path": "/debug",
            "signal": "config_exposure_pattern",
            "exposed_keys": ["secret_key", "valid_usernames"],
        }
    )

    findings = detect_config_exposure([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CONFIG-EXPOSURE-001"
    assert finding.severity == "High"
    assert "secret_key" in finding.reason


def test_rule_ignores_disabled_endpoint_event():
    event = make_event(
        {
            "event_type": "config_exposure",
            "request_path": "/debug",
            "signal": None,
            "exposed_keys": [],
        }
    )

    assert detect_config_exposure([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "config_exposure_pattern"})
    assert detect_config_exposure([event]) == []
