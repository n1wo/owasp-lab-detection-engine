"""Tests for the lab overview/home page and the relocated login form."""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_APP_ROOT = ROOT / "vulnerable-app"
sys.path.insert(0, str(VULNERABLE_APP_ROOT))

from vulnerable_app import create_app  # noqa: E402


def make_app(tmp_path, mode="insecure"):
    return create_app({"LAB_MODE": mode, "LAB_LOG_FILE": tmp_path / "app.jsonl"})


def test_root_serves_overview_not_login_form(tmp_path):
    response = make_app(tmp_path).test_client().get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # Overview content, not a login form.
    assert "detection engineering lab" in body
    assert "How it works" in body
    assert 'action="/login"' not in body  # the login POST form is on /login now


def test_overview_links_to_every_scenario(tmp_path):
    body = make_app(tmp_path).test_client().get("/").get_data(as_text=True)

    for href in ('href="/login"', 'href="/search"', 'href="/comment"', 'href="/dashboard"'):
        assert href in body
    for rule in ("AUTH-BRUTE-FORCE-001", "WEB-SQLI-PATTERN-001", "WEB-XSS-PATTERN-001", "BAC-PRIV-ESC-001"):
        assert rule in body


def test_overview_shows_demo_credentials_and_toggle(tmp_path):
    body = make_app(tmp_path).test_client().get("/").get_data(as_text=True)

    assert "test-user / lab-password" in body
    assert "admin / admin-password" in body
    assert "lab console" in body.lower()


def test_overview_shows_docker_requirement_banner(tmp_path):
    body = make_app(tmp_path).test_client().get("/").get_data(as_text=True)

    assert "Docker is required to run the lab app." in body
    assert "docker compose up --build" in body


def test_login_form_served_at_login_path(tmp_path):
    response = make_app(tmp_path).test_client().get("/login")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'action="/login"' in body
    assert 'name="password"' in body


def test_login_still_redirects_to_dashboard(tmp_path):
    client = make_app(tmp_path, mode="secure").test_client()

    response = client.post("/login", data={"username": "test-user", "password": "lab-password"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard?username=test-user")


def test_logout_returns_to_login(tmp_path):
    client = make_app(tmp_path).test_client()
    client.post("/login", data={"username": "admin", "password": "admin-password"})

    response = client.get("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
