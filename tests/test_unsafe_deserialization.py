"""Tests for the unsafe serialized profile import scenario."""

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
from detection_engine.rules import detect_unsafe_deserialization  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "profile_import"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "test-user"),
        raw=raw,
    )


def attack_payload():
    return json.dumps(
        {
            "display_name": "test-user",
            "theme": "dark",
            "timezone": "UTC",
            "role": "admin",
            "feature_flags": ["admin_panel"],
        }
    )


# --- App behavior ----------------------------------------------------------


def test_insecure_profile_import_trusts_privileged_fields(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/profile/import", data={"payload": attack_payload()})

    assert response.status_code == 200
    assert b"Privileged client-controlled fields were trusted" in response.data
    assert b"role" in response.data
    assert b"admin" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "profile_import"
    assert event["signal"] == "unsafe_deserialization_pattern"
    assert event["reason"] == "trusted_serialized_privileged_fields"
    assert event["success"] is True
    assert event["request_path"] == "/profile/import"
    assert event["privileged_keys"] == ["feature_flags", "role"]
    assert "role" in event["trusted_keys"]


def test_secure_profile_import_rejects_privileged_fields(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/profile/import", data={"payload": attack_payload()})

    assert response.status_code == 400
    assert b"Profile import rejected" in response.data
    assert b"Trusted profile" not in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "profile_import"
    assert event["signal"] is None
    assert event["reason"] == "rejected_privileged_serialized_fields"
    assert event["success"] is False
    assert event["privileged_keys"] == ["feature_flags", "role"]


def test_secure_profile_import_accepts_safe_preferences(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})
    payload = json.dumps({"display_name": "test-user", "theme": "dark", "timezone": "UTC"})

    response = app.test_client().post("/profile/import", data={"payload": payload})

    assert response.status_code == 200
    assert b"allowlist validation" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "profile_import"
    assert event["signal"] is None
    assert event["reason"] == "validated_profile_import"
    assert event["trusted_keys"] == ["display_name", "theme", "timezone"]


def test_invalid_profile_import_payload_logs_failed_attempt(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/profile/import", data={"payload": "{not json"})

    assert response.status_code == 400
    assert b"valid JSON" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "profile_import"
    assert event["signal"] is None
    assert event["reason"] == "invalid_profile_payload"
    assert event["success"] is False


def test_profile_import_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/profile/import")
    assert response.status_code == 200
    assert b"Profile import" in response.data
    assert b"INTEGRITY-DESERIALIZE-001" in response.data


def test_home_page_lists_profile_import_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"INTEGRITY-DESERIALIZE-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_unsafe_profile_import():
    event = make_event(
        {
            "event_type": "profile_import",
            "signal": "unsafe_deserialization_pattern",
            "privileged_keys": ["role", "feature_flags"],
            "request_path": "/profile/import",
        }
    )

    findings = detect_unsafe_deserialization([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "INTEGRITY-DESERIALIZE-001"
    assert finding.severity == "High"
    assert "role" in finding.reason
    assert "/profile/import" in finding.reason


def test_rule_ignores_validated_profile_import():
    event = make_event(
        {
            "event_type": "profile_import",
            "signal": None,
            "privileged_keys": [],
        }
    )

    assert detect_unsafe_deserialization([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "unsafe_deserialization_pattern"})
    assert detect_unsafe_deserialization([event]) == []
