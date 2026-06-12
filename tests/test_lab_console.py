"""Tests for the floating lab console: nav, mode toggle, and /soc route."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
sys.path.insert(0, str(VULNERABLE_APP_ROOT))

from vulnerable_app import create_app  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    """Create a lab app instance writing telemetry into the test tmp dir."""

    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_nav_console_present_on_all_pages(tmp_path):
    client = make_app(tmp_path).test_client()

    for path in ("/", "/search", "/comment", "/dashboard"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'id="labnav"' in response.data
        assert b'action="/lab/mode"' in response.data
        assert b'href="/soc"' in response.data


def test_mode_toggle_switches_mode_and_logs_event(tmp_path):
    log_file = tmp_path / "app.jsonl"
    app = create_app({"LAB_MODE": "insecure", "LAB_LOG_FILE": log_file})
    client = app.test_client()

    assert client.get("/health").get_json()["mode"] == "insecure"

    response = client.post("/lab/mode", data={"next": "/search"})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/search")
    assert client.get("/health").get_json()["mode"] == "secure"

    events = read_jsonl(log_file)
    assert events[-1]["event_type"] == "lab_mode_change"
    assert "insecure to secure" in events[-1]["reason"]

    client.post("/lab/mode")
    assert client.get("/health").get_json()["mode"] == "insecure"


def test_mode_toggle_changes_login_behavior_at_runtime(tmp_path):
    client = make_app(tmp_path, mode="insecure").test_client()

    insecure = client.post("/login", data={"username": "ghost", "password": "x"})
    assert b"Unknown user." in insecure.data

    client.post("/lab/mode")

    secure = client.post("/login", data={"username": "ghost", "password": "x"})
    assert b"Invalid username or password." in secure.data
    assert b"Unknown user." not in secure.data


def test_mode_toggle_changes_xss_comment_behavior_at_runtime(tmp_path):
    client = make_app(tmp_path, mode="insecure").test_client()
    payload = {"comment": "<script>alert(1)</script>"}

    insecure = client.post("/comment", data=payload)
    assert insecure.status_code == 200
    assert b"<script>alert(1)</script>" in insecure.data

    client.post("/lab/mode")

    secure = client.post("/comment", data=payload)
    assert secure.status_code == 400
    assert b"Comment input was rejected." in secure.data
    assert b"<script>alert(1)</script>" not in secure.data


def test_mode_toggle_rejects_unsafe_redirect_targets(tmp_path):
    client = make_app(tmp_path).test_client()

    for unsafe in ("https://evil.example", "//evil.example"):
        response = client.post("/lab/mode", data={"next": unsafe})
        assert response.status_code == 302
        assert "evil.example" not in response.headers["Location"]


def test_soc_route_shows_live_empty_state_when_report_missing(tmp_path):
    client = make_app(tmp_path).test_client()

    response = client.get("/soc")

    assert response.status_code == 200
    assert b"Live SOC Alerts" in response.data
    assert b"No live alerts yet" in response.data


def test_soc_route_shows_unknown_username_alert(tmp_path):
    client = make_app(tmp_path).test_client()

    client.post("/login", data={"username": "ghost-user", "password": "wrong"})
    response = client.get("/soc")

    assert response.status_code == 200
    assert b"Unknown username login attempt" in response.data
    assert b"AUTH-UNKNOWN-USER-LOCAL" in response.data
    assert b"ghost-user" in response.data
    assert b"unknown_user" in response.data


def test_soc_route_serves_generated_report(tmp_path):
    report = tmp_path / "findings.html"
    report.write_text("<!doctype html><title>findings</title>SOC-REPORT-MARKER", encoding="utf-8")
    client = make_app(tmp_path).test_client()

    response = client.get("/soc")

    assert response.status_code == 200
    assert b"SOC-REPORT-MARKER" in response.data
