"""Tests for the SSRF (server-side request forgery) fetch scenario."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
sys.path.insert(0, str(VULNERABLE_APP_ROOT))

from vulnerable_app import create_app  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_fetch_page_renders(tmp_path):
    response = make_app(tmp_path).test_client().get("/fetch")
    assert response.status_code == 200
    assert b"URL fetcher" in response.data


def test_metadata_fetch_succeeds_in_insecure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/fetch", data={"url": "http://169.254.169.254/latest/meta-data/"})

    assert response.status_code == 200
    assert b"simulated cloud metadata response" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "outbound_request"
    assert event["signal"] == "ssrf_internal_target_pattern"
    assert event["reason"] == "fetched_internal_target"
    assert event["target_host"] == "169.254.169.254"
    assert event["success"] is True


def test_metadata_fetch_blocked_in_secure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/fetch", data={"url": "http://169.254.169.254/latest/meta-data/"})

    assert response.status_code == 400
    assert b"blocked" in response.data.lower()

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "outbound_request"
    assert event["signal"] == "ssrf_internal_target_pattern"
    assert event["reason"] == "blocked_internal_target"
    assert event["success"] is False


def test_loopback_and_private_targets_are_flagged(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})
    client = app.test_client()

    for url in (
        "http://127.0.0.1/admin",
        "http://localhost/admin",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/",
        "file:///etc/passwd",
    ):
        client.post("/fetch", data={"url": url})

    events = [e for e in read_jsonl(log_file) if e["event_type"] == "outbound_request"]
    assert len(events) == 5
    assert all(e["signal"] == "ssrf_internal_target_pattern" for e in events)


def test_external_target_is_not_flagged(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/fetch", data={"url": "https://example.com/status"})

    assert response.status_code == 200
    outbound = [e for e in read_jsonl(log_file) if e["event_type"] == "outbound_request"]
    assert outbound == []


def test_external_target_blocked_in_secure_mode_is_allowed(tmp_path):
    # Secure mode should still serve a legitimate external URL.
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post("/fetch", data={"url": "https://example.com/status"})

    assert response.status_code == 200
