"""Tests for the localhost-only login demo activity generator."""

import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import generate_login_demo as demo  # noqa: E402


class FakeResponse:
    status = 401


class FakeOpener:
    def open(self, request, timeout=3.0):
        """Return a fake failed-login response without making a network call."""

        return FakeResponse()


class FakeHttpErrorOpener:
    def open(self, request, timeout=3.0):
        """Raise a fake HTTP 401 error like urllib does for failed logins."""

        raise HTTPError(request.full_url, 401, "UNAUTHORIZED", hdrs=None, fp=None)


def test_validate_local_base_url_allows_localhost_and_loopback():
    """Verify the demo accepts only the intended local hostnames."""

    assert demo.validate_local_base_url("http://localhost:8080") == "http://localhost:8080"
    assert demo.validate_local_base_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"


def test_validate_local_base_url_rejects_non_local_targets():
    """Verify the demo refuses non-local or malformed base URLs."""

    for url in [
        "https://127.0.0.1:8080",
        "http://example.com",
        "http://192.168.1.10:8080",
        "http://localhost:8080/remote/path",
    ]:
        try:
            demo.validate_local_base_url(url)
        except ValueError:
            continue
        raise AssertionError(f"expected URL to be rejected: {url}")


def test_build_demo_attempts_generates_threshold_failures_and_optional_success():
    """Verify the default demo sequence triggers the brute-force threshold."""

    attempts = demo.build_demo_attempts(include_success=True)

    assert len(attempts) == 6
    assert sum(1 for attempt in attempts if not attempt.expected_success) == 5
    assert sum(1 for attempt in attempts if attempt.expected_success) == 1
    assert {attempt.username for attempt in attempts} == {"test-user"}


def test_build_demo_attempts_can_skip_success():
    """Verify the demo can generate only failed login attempts."""

    attempts = demo.build_demo_attempts(include_success=False)

    assert len(attempts) == 5
    assert all(not attempt.expected_success for attempt in attempts)


def test_send_login_attempts_builds_opener_with_handler_instance(monkeypatch):
    """Verify requests use the no-redirect handler so 302 statuses are visible."""

    observed_handlers = []

    def fake_build_opener(*handlers):
        """Capture opener handlers and return a fake opener for the test."""

        observed_handlers.extend(handlers)
        return FakeOpener()

    monkeypatch.setattr(demo, "build_opener", fake_build_opener)

    statuses = demo.send_login_attempts(
        "http://127.0.0.1:8080",
        [demo.LoginAttempt("test-user", "wrong-local-demo-password", expected_success=False)],
    )

    assert statuses == [401]
    assert len(observed_handlers) == 1
    assert isinstance(observed_handlers[0], demo.NoRedirectHandler)
    assert isinstance(observed_handlers[0], HTTPRedirectHandler)


def test_send_login_attempts_records_expected_http_error_statuses(monkeypatch):
    """Verify failed-login HTTP errors are recorded as statuses, not fatal."""

    monkeypatch.setattr(demo, "build_opener", lambda *handlers: FakeHttpErrorOpener())

    statuses = demo.send_login_attempts(
        "http://127.0.0.1:8080",
        [demo.LoginAttempt("test-user", "wrong-local-demo-password", expected_success=False)],
    )

    assert statuses == [401]


def test_main_prints_helpful_message_when_app_is_unavailable(monkeypatch, capsys):
    """Verify the CLI explains how to start the app when /health is down."""

    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: False)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Start it first with: docker compose up --build" in captured.err
