"""Tests for the cryptographic failures password-storage scenario."""

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
from detection_engine.rules import detect_weak_crypto  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_event(raw):
    return LogEvent(
        timestamp=datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        event_type=raw.get("event_type", "credential_storage"),
        source_ip=raw.get("source_ip", "127.0.0.1"),
        username=raw.get("username", "lab-user"),
        raw=raw,
    )


# --- App behavior ----------------------------------------------------------


def test_insecure_mode_stores_unsalted_md5(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/register", data={"username": "lab-user", "password": "hunter2"}
    )

    assert response.status_code == 200
    # MD5 of "hunter2" is deterministic and unsalted.
    assert b"f3bbbd66a63d4bf1747940578ec3d0103530e21d" not in response.data  # sha1, not md5
    assert b"md5" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "credential_storage"
    assert event["signal"] == "weak_password_hash_pattern"
    assert event["algorithm"] == "md5"
    assert event["salted"] is False
    assert event["reason"] == "weak_password_hash"


def test_secure_mode_stores_salted_pbkdf2(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/register", data={"username": "lab-user", "password": "hunter2"}
    )

    assert response.status_code == 200
    assert b"pbkdf2_sha256" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "credential_storage"
    assert event["signal"] is None
    assert event["algorithm"] == "pbkdf2_sha256"
    assert event["salted"] is True
    assert event["reason"] == "strong_password_hash"


def test_secure_mode_salts_differ_for_same_password(tmp_path):
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": tmp_path / "app.jsonl"})
    client = app.test_client()

    first = client.post("/register", data={"username": "a", "password": "same"}).data
    second = client.post("/register", data={"username": "b", "password": "same"}).data

    # Salting means identical passwords produce different stored values.
    assert first != second


def test_empty_password_is_rejected(tmp_path):
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": tmp_path / "app.jsonl"})
    response = app.test_client().post("/register", data={"username": "lab-user"})
    assert response.status_code == 400


def test_register_form_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/register")
    assert response.status_code == 200
    assert b"Create account" in response.data


def test_home_page_lists_crypto_scenario(tmp_path):
    response = make_app(tmp_path).test_client().get("/")
    assert b"CRYPTO-WEAK-001" in response.data


# --- Detection rule --------------------------------------------------------


def test_rule_flags_weak_hash_event():
    event = make_event(
        {
            "event_type": "credential_storage",
            "signal": "weak_password_hash_pattern",
            "algorithm": "md5",
            "salted": False,
        }
    )

    findings = detect_weak_crypto([event])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CRYPTO-WEAK-001"
    assert finding.severity == "High"
    assert "md5" in finding.reason


def test_rule_ignores_strong_hash_event():
    event = make_event(
        {
            "event_type": "credential_storage",
            "signal": None,
            "algorithm": "pbkdf2_sha256",
            "salted": True,
        }
    )

    assert detect_weak_crypto([event]) == []


def test_rule_ignores_unrelated_events():
    event = make_event({"event_type": "login_failure", "signal": "weak_password_hash_pattern"})
    assert detect_weak_crypto([event]) == []
