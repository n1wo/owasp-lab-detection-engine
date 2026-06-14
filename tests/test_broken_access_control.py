"""Tests for the broken access control admin-panel scenario."""

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
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_admin_panel_denied_by_default(tmp_path):
    response = make_app(tmp_path).test_client().get("/dashboard")

    assert response.status_code == 403
    assert b"Access denied" in response.data
    assert b"Admin panel" not in response.data


def test_role_param_exploit_grants_access_in_insecure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get("/dashboard?role=admin")

    assert response.status_code == 200
    assert b"Admin panel" in response.data
    assert b"broken access control" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "admin_access"
    assert event["granted"] is True
    assert event["signal"] == "broken_access_control_pattern"
    assert event["reason"] == "broken_access_control_role_param"


def test_role_param_exploit_blocked_in_secure_mode(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})

    response = app.test_client().get("/dashboard?role=admin")

    assert response.status_code == 403
    assert b"Access denied" in response.data

    event = read_jsonl(log_file)[-1]
    assert event["event_type"] == "admin_access"
    assert event["granted"] is False


def test_admin_login_reaches_panel_legitimately_in_both_modes(tmp_path):
    for mode in ("insecure", "secure"):
        client = make_app(tmp_path, mode=mode).test_client()
        client.post("/login", data={"username": "admin", "password": "admin-password"})

        response = client.get("/dashboard")

        assert response.status_code == 200, mode
        assert b"Admin panel" in response.data
        # Legitimate session access is not flagged as an exploit.
        assert b"broken access control" not in response.data


def test_regular_user_login_does_not_grant_admin(tmp_path):
    client = make_app(tmp_path, mode="insecure").test_client()
    client.post("/login", data={"username": "test-user", "password": "lab-password"})

    response = client.get("/dashboard")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_secure_admin_dashboard_ignores_spoofed_username_query(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "secure", "LAB_LOG_FILE": log_file})
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin-password"})

    response = client.get("/dashboard?username=evil-user")

    assert response.status_code == 200
    assert b"viewing as: <strong>admin</strong>" in response.data
    assert b"evil-user" not in response.data

    event = [e for e in read_jsonl(log_file) if e["event_type"] == "admin_access"][-1]
    assert event["username"] == "admin"
    assert event["reason"] == "authorized_admin_session"


def test_exploit_path_logged_distinctly_from_legit_admin(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})
    client = app.test_client()

    client.post("/login", data={"username": "admin", "password": "admin-password"})
    client.get("/dashboard")  # legit
    client.get("/logout")
    client.get("/dashboard?role=admin")  # exploit

    admin_events = [e for e in read_jsonl(log_file) if e["event_type"] == "admin_access" and e["granted"]]
    reasons = {e["reason"] for e in admin_events}
    assert "authorized_admin_session" in reasons
    assert "broken_access_control_role_param" in reasons


def test_logout_clears_admin_session(tmp_path):
    client = make_app(tmp_path, mode="secure").test_client()
    client.post("/login", data={"username": "admin", "password": "admin-password"})
    assert client.get("/dashboard").status_code == 200

    client.get("/logout")

    assert client.get("/dashboard").status_code == 403
