"""Tests for the software-supply-chain component-sync scenario."""

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
from vulnerable_app.app import COMPONENT_MANIFEST_SAMPLE, PINNED_COMPONENTS  # noqa: E402
from detection_engine.models import LogEvent  # noqa: E402
from detection_engine.rules import detect_supply_chain  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "dependency_load"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "anonymous"),
        raw=raw,
    )


def verified_manifest():
    return json.dumps(
        [{"name": name, "version": "1.0.0", "integrity": pinned} for name, pinned in PINNED_COMPONENTS.items()]
    )


# --- App behavior ----------------------------------------------------------


def test_insecure_sync_installs_unverified_component(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/integrations", data={"manifest": COMPONENT_MANIFEST_SAMPLE})

    assert response.status_code == 200
    assert b"without integrity checks" in response.data
    assert b"tampered" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "dependency_load"
    assert event["signal"] == "supply_chain_compromise_pattern"
    assert event["reason"] == "unverified_component_integrity"
    assert event["success"] is True
    assert event["request_path"] == "/integrations"
    assert event["compromised_components"] == ["payment-widget"]


def test_secure_sync_rejects_tampered_component(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/integrations", data={"manifest": COMPONENT_MANIFEST_SAMPLE})

    assert response.status_code == 400
    assert b"integrity verification failed" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "dependency_load"
    assert event["signal"] is None
    assert event["reason"] == "rejected_untrusted_component"
    assert event["success"] is False
    assert event["compromised_components"] == ["payment-widget"]


def test_insecure_sync_of_verified_manifest_raises_no_signal(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/integrations", data={"manifest": verified_manifest()})

    assert response.status_code == 200
    assert b"matched the pinned integrity baseline" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["signal"] is None
    assert event["reason"] == "verified_component_integrity"
    assert event["compromised_components"] == []


def test_secure_sync_of_verified_manifest_succeeds(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/integrations", data={"manifest": verified_manifest()})

    assert response.status_code == 200

    event = read_jsonl(log_file)[-1]
    assert event["signal"] is None
    assert event["reason"] == "verified_component_integrity"
    assert event["success"] is True


def test_invalid_manifest_logs_failed_attempt(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/integrations", data={"manifest": "{not json"})

    assert response.status_code == 400
    assert b"valid JSON" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["signal"] is None
    assert event["reason"] == "invalid_component_manifest"
    assert event["success"] is False


def test_integrations_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/integrations")
    assert response.status_code == 200
    assert b"Component sync" in response.data
    assert b"SUPPLY-CHAIN-001" in response.data


def test_home_page_lists_integrations_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"SUPPLY-CHAIN-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_unverified_component_load():
    event = make_event(
        {
            "event_type": "dependency_load",
            "signal": "supply_chain_compromise_pattern",
            "request_path": "/integrations",
            "compromised_components": ["payment-widget"],
        }
    )

    findings = detect_supply_chain([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SUPPLY-CHAIN-001"
    assert finding.severity == "High"
    assert "payment-widget" in finding.reason
    assert "/integrations" in finding.reason


def test_rule_ignores_verified_sync():
    event = make_event(
        {
            "event_type": "dependency_load",
            "signal": None,
            "compromised_components": [],
        }
    )

    assert detect_supply_chain([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "supply_chain_compromise_pattern"})
    assert detect_supply_chain([event]) == []
