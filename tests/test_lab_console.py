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

    for path in ("/", "/login", "/search", "/comment"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'id="labnav"' in response.data
        assert b'action="/lab/mode"' in response.data
        assert b'href="/soc"' in response.data


def test_brand_links_back_to_home_on_lab_pages(tmp_path):
    client = make_app(tmp_path).test_client()

    for path in ("/", "/login", "/search", "/comment", "/dashboard", "/soc"):
        response = client.get(path)
        assert response.status_code in (200, 403)
        assert b'<a class="brand" href="/">' in response.data


def test_help_popup_present_on_each_scenario_page(tmp_path):
    # Every scenario page exposes a "?" button that opens a modal explaining
    # the vulnerability, tagged with its detection rule id.
    client = make_app(tmp_path).test_client()
    expected = {
        "/login": b"AUTH-BRUTE-FORCE-001",
        "/search": b"WEB-SQLI-PATTERN-001",
        "/comment": b"WEB-XSS-PATTERN-001",
        "/dashboard": b"BAC-PRIV-ESC-001",  # access-denied gate
        "/dashboard?role=admin": b"BAC-PRIV-ESC-001",  # admin panel
        "/fetch": b"WEB-SSRF-INTERNAL-001",
    }
    for path, rule_id in expected.items():
        response = client.get(path)
        assert b'class="help-btn"' in response.data, path
        assert b'class="help-modal"' in response.data, path
        assert b"onclick=\"openHelp()\"" in response.data, path
        assert b".help-btn {\n        position: absolute;" in response.data, path
        assert rule_id in response.data, path


def test_help_popup_absent_from_home_and_soc(tmp_path):
    # The help "?" affordance is scoped to scenario pages, not the overview.
    client = make_app(tmp_path).test_client()

    for path in ("/", "/soc"):
        assert b'class="help-btn"' not in client.get(path).data, path


def _nav_block(html):
    """Return just the lab console <nav> markup from a page."""

    start = html.index('<nav class="labnav"')
    return html[start : html.index("</nav>", start)]


def test_nav_console_does_not_link_to_admin_panel(tmp_path):
    # The admin panel must only be reachable via the broken-access-control
    # exploit, so the console must not advertise a direct link to it.
    html = make_app(tmp_path).test_client().get("/search").get_data(as_text=True)
    assert 'href="/dashboard"' not in _nav_block(html)
    # The console (and 403 page) still render on the gated route.
    denied = make_app(tmp_path).test_client().get("/dashboard")
    assert denied.status_code == 403
    assert b'id="labnav"' in denied.data


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


def test_soc_route_shows_broken_access_control_alert(tmp_path):
    client = make_app(tmp_path).test_client()

    client.get("/dashboard?role=admin")  # the broken-access-control exploit
    response = client.get("/soc")

    assert response.status_code == 200
    assert b"Privilege escalation to admin panel" in response.data
    assert b"BAC-PRIV-ESC-001" in response.data


def test_soc_route_serves_generated_report(tmp_path):
    report = tmp_path / "findings.html"
    report.write_text("<!doctype html><title>findings</title>SOC-REPORT-MARKER", encoding="utf-8")
    client = make_app(tmp_path).test_client()

    response = client.get("/soc")

    assert response.status_code == 200
    assert b"SOC-REPORT-MARKER" in response.data
