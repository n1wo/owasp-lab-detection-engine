"""Tests for the localhost-only SQLi-like search demo activity generator."""

import sys
from pathlib import Path
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import generate_sqli_demo as demo  # noqa: E402


class FakeResponse:
    status = 200


class FakeOpener:
    def open(self, request, timeout=3.0):
        """Return a fake successful search response without network access."""

        return FakeResponse()


class FakeHttpErrorOpener:
    def open(self, request, timeout=3.0):
        """Raise a fake HTTP 400 error like secure mode can return."""

        raise HTTPError(request.full_url, 400, "BAD REQUEST", hdrs=None, fp=None)


def test_validate_local_base_url_allows_localhost_and_loopback():
    """Verify the SQLi demo accepts only intended local hostnames."""

    assert demo.validate_local_base_url("http://localhost:8080") == "http://localhost:8080"
    assert demo.validate_local_base_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"


def test_validate_local_base_url_rejects_non_local_targets():
    """Verify the SQLi demo refuses non-local or malformed base URLs."""

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


def test_send_search_attempt_records_success_status(monkeypatch):
    """Verify insecure-mode success responses are returned as statuses."""

    monkeypatch.setattr(demo, "build_opener", lambda: FakeOpener())

    status = demo.send_search_attempt("http://127.0.0.1:8080")

    assert status == 200


def test_send_search_attempt_records_expected_http_error_status(monkeypatch):
    """Verify secure-mode HTTP errors are returned as statuses."""

    monkeypatch.setattr(demo, "build_opener", lambda: FakeHttpErrorOpener())

    status = demo.send_search_attempt("http://127.0.0.1:8080")

    assert status == 400


def test_main_prints_helpful_message_when_app_is_unavailable(monkeypatch, capsys):
    """Verify the CLI explains how to start the app when /health is down."""

    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: False)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Start it first with: docker compose up --build" in captured.err


def test_main_prints_helpful_message_for_unexpected_status(monkeypatch, capsys):
    """Verify the CLI explains stale app builds when /search is unavailable."""

    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: True)
    monkeypatch.setattr(demo, "send_search_attempt", lambda base_url, timeout=3.0: 404)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Rebuild and restart the app" in captured.err
