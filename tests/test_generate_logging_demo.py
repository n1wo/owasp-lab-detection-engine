"""Tests for the localhost-only logging-failure demo activity generator."""

import sys
from pathlib import Path
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import generate_logging_demo as demo  # noqa: E402


class FakeResponse:
    status = 200

    def read(self):
        return b""


class FakeOpener:
    def __init__(self):
        self.paths = []

    def open(self, request, timeout=3.0):
        """Return fake successful responses without network access."""

        self.paths.append(request.full_url)
        return FakeResponse()


def test_validate_local_base_url_allows_localhost_and_loopback():
    """Verify the logging demo accepts only intended local hostnames."""

    assert demo.validate_local_base_url("http://localhost:8080") == "http://localhost:8080"
    assert demo.validate_local_base_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"


def test_validate_local_base_url_rejects_non_local_targets():
    """Verify the logging demo refuses non-local or malformed base URLs."""

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


def test_send_role_change_attempt_records_success_status(monkeypatch):
    """Verify insecure-mode success responses are returned as statuses."""

    opener = FakeOpener()
    monkeypatch.setattr(demo, "build_opener", lambda *args: opener)

    status = demo.send_role_change_attempt("http://127.0.0.1:8080")

    assert status == 200
    assert opener.paths == [
        "http://127.0.0.1:8080/login",
        "http://127.0.0.1:8080/admin/role",
    ]


def test_main_prints_helpful_message_when_app_is_unavailable(monkeypatch, capsys):
    """Verify the CLI explains how to start the app when /health is down."""

    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: False)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Start it first with: docker compose up --build" in captured.err


def test_main_prints_helpful_message_for_unexpected_status(monkeypatch, capsys):
    """Verify the CLI explains stale app builds when /admin/role is unavailable."""

    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: True)
    monkeypatch.setattr(demo, "send_role_change_attempt", lambda base_url, timeout=3.0: 404)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Rebuild and restart the app" in captured.err
