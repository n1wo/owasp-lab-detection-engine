"""Tests for vulnerable-app lab modes and structured telemetry."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
# The source folder keeps the requested hyphenated name, so tests add it
# explicitly instead of importing it as a Python package name.
sys.path.insert(0, str(VULNERABLE_APP_ROOT))

from vulnerable_app import create_app  # noqa: E402


REQUIRED_LOGIN_FIELDS = {
    "timestamp",
    "event_type",
    "source_ip",
    "username",
    "user_agent",
    "request_path",
    "http_method",
    "status_code",
    "lab_mode",
    "reason",
    "session_id",
}


def read_jsonl(path):
    """Read every JSONL line from a test log file into dictionaries."""

    return [json.loads(line) for line in path.read_text().splitlines()]


def test_health_reports_configured_mode(tmp_path):
    """Verify /health reports both readiness and the configured lab mode."""

    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": tmp_path / "app.jsonl"})

    response = app.test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"mode": "secure", "status": "ok"}


def test_insecure_login_failure_uses_lab_specific_message_and_logs(tmp_path):
    """Verify insecure mode exposes lab-specific errors and logs telemetry."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/login",
        data={"username": "not-a-user", "password": "wrong"},
    )

    assert response.status_code == 401
    assert b"Unknown user." in response.data

    events = read_jsonl(log_file)
    assert len(events) == 1
    assert REQUIRED_LOGIN_FIELDS.issubset(events[0])
    assert events[0]["event_type"] == "login_failure"
    assert events[0]["lab_mode"] == "insecure"
    assert events[0]["reason"] == "unknown_user"
    assert events[0]["source_ip"] == "127.0.0.1"
    assert events[0]["request_path"] == "/login"
    assert events[0]["http_method"] == "POST"
    assert events[0]["session_id"] is None


def test_successful_login_redirects_and_logs(tmp_path):
    """Verify successful login redirects and emits a login_success event."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/login",
        data={"username": "test-user", "password": "lab-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard?username=test-user")

    events = read_jsonl(log_file)
    assert REQUIRED_LOGIN_FIELDS.issubset(events[0])
    assert events[0]["event_type"] == "login_success"
    assert events[0]["success"] is True
    assert events[0]["username"] == "test-user"
    assert events[0]["lab_mode"] == "secure"
    assert events[0]["request_path"] == "/login"


def test_secure_mode_blocks_after_repeated_failures(tmp_path):
    """Verify secure mode locks a source/user pair after repeated failures."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})
    client = app.test_client()

    for _ in range(5):
        response = client.post(
            "/login",
            data={"username": "test-user", "password": "wrong"},
        )
        assert response.status_code == 401
        assert b"Invalid username or password." in response.data

    blocked = client.post(
        "/login",
        data={"username": "test-user", "password": "wrong"},
    )

    assert blocked.status_code == 429
    assert b"Too many failed attempts" in blocked.data

    events = read_jsonl(log_file)
    assert [event["event_type"] for event in events][-1] == "account_lockout"
    assert events[-1]["reason"] == "too_many_failures"


def test_insecure_search_accepts_sqli_like_input_and_logs_signal(tmp_path):
    """Verify insecure search accepts SQLi-like input and logs a signal."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get(
        "/search",
        query_string={"q": "test-user' OR '1'='1"},
        headers={"User-Agent": "pytest-local"},
    )

    assert response.status_code == 200
    assert b"Insecure mode accepted suspicious-looking search input." in response.data
    assert b"Local lab result: admin profile" in response.data

    events = read_jsonl(log_file)
    assert len(events) == 1
    assert events[0]["event_type"] == "suspicious_input"
    assert events[0]["signal"] == "sql_injection_like_pattern"
    assert events[0]["lab_mode"] == "insecure"
    assert events[0]["reason"] == "accepted_suspicious_input"
    assert events[0]["source_ip"] == "127.0.0.1"
    assert events[0]["username"] == "anonymous"
    assert events[0]["request_path"] == "/search"
    assert events[0]["http_method"] == "GET"
    assert events[0]["status_code"] == 200
    assert events[0]["success"] is True
    assert events[0]["input_name"] == "q"


def test_secure_search_rejects_sqli_like_input_and_logs_signal(tmp_path):
    """Verify secure search rejects SQLi-like input and logs the attempt."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get(
        "/search",
        query_string={"q": "test-user' OR '1'='1"},
    )

    assert response.status_code == 400
    assert b"Search input was rejected." in response.data
    assert b"Local lab result: admin profile" not in response.data

    events = read_jsonl(log_file)
    assert len(events) == 1
    assert events[0]["event_type"] == "suspicious_input"
    assert events[0]["signal"] == "sql_injection_like_pattern"
    assert events[0]["lab_mode"] == "secure"
    assert events[0]["reason"] == "rejected_suspicious_input"
    assert events[0]["status_code"] == 400
    assert events[0]["success"] is False


def test_search_normal_query_does_not_emit_suspicious_input_log(tmp_path):
    """Verify ordinary search input renders without suspicious-input telemetry."""

    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get("/search", query_string={"q": "test-user"})

    assert response.status_code == 200
    assert b"Local lab result for test-user" in response.data
    assert not log_file.exists()
