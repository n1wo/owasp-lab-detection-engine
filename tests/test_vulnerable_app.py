import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
# The source folder keeps the requested hyphenated name, so tests add it
# explicitly instead of importing it as a Python package name.
sys.path.insert(0, str(VULNERABLE_APP_ROOT))

from vulnerable_app import create_app  # noqa: E402


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_health_reports_configured_mode(tmp_path):
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": tmp_path / "app.jsonl"})

    response = app.test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"mode": "secure", "status": "ok"}


def test_insecure_login_failure_uses_lab_specific_message_and_logs(tmp_path):
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
    assert events[0]["event_type"] == "login_failure"
    assert events[0]["mode"] == "insecure"
    assert events[0]["reason"] == "unknown_user"
    assert events[0]["source_ip"] == "127.0.0.1"


def test_successful_login_redirects_and_logs(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().post(
        "/login",
        data={"username": "test-user", "password": "lab-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard?username=test-user")

    events = read_jsonl(log_file)
    assert events[0]["event_type"] == "login_success"
    assert events[0]["success"] is True
    assert events[0]["username"] == "test-user"


def test_secure_mode_blocks_after_repeated_failures(tmp_path):
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
    assert [event["event_type"] for event in events][-1] == "login_blocked"
    assert events[-1]["reason"] == "too_many_failures"
