import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import generate_login_demo as demo  # noqa: E402


def test_validate_local_base_url_allows_localhost_and_loopback():
    assert demo.validate_local_base_url("http://localhost:8080") == "http://localhost:8080"
    assert demo.validate_local_base_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"


def test_validate_local_base_url_rejects_non_local_targets():
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
    attempts = demo.build_demo_attempts(include_success=True)

    assert len(attempts) == 6
    assert sum(1 for attempt in attempts if not attempt.expected_success) == 5
    assert sum(1 for attempt in attempts if attempt.expected_success) == 1
    assert {attempt.username for attempt in attempts} == {"test-user"}


def test_build_demo_attempts_can_skip_success():
    attempts = demo.build_demo_attempts(include_success=False)

    assert len(attempts) == 5
    assert all(not attempt.expected_success for attempt in attempts)


def test_main_prints_helpful_message_when_app_is_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(demo, "app_is_available", lambda base_url, timeout=3.0: False)

    exit_code = demo.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Start it first with: docker compose up --build" in captured.err

