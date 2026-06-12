"""Tests for the HTML dashboard report and the CLI --html option."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DETECTION_ENGINE_ROOT = ROOT / "detection-engine"
sys.path.insert(0, str(DETECTION_ENGINE_ROOT))

from detection_engine.__main__ import main  # noqa: E402
from detection_engine.models import DetectionFinding, ParseError  # noqa: E402
from detection_engine.report import render_html_report  # noqa: E402


def sample_finding(**overrides):
    """Build a representative brute-force finding for report tests."""

    defaults = {
        "rule_id": "AUTH-BRUTE-FORCE-001",
        "severity": "Medium",
        "source_ip": "127.0.0.1",
        "username": "test-user",
        "event_count": 6,
        "first_seen": datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 6, 2, 9, 4, tzinfo=timezone.utc),
        "reason": "6 login_failure events for user 'test-user' from 127.0.0.1 within 5 minutes",
    }
    defaults.update(overrides)
    return DetectionFinding(**defaults)


def test_report_renders_findings_and_summary():
    finding = sample_finding()
    html = render_html_report([finding], [], log_file="logs/application.jsonl", event_count=42)

    assert "<!doctype html>" in html
    assert "AUTH-BRUTE-FORCE-001" in html
    assert "sev-medium" in html
    assert "127.0.0.1" in html
    assert "test-user" in html
    assert "logs/application.jsonl" in html
    assert "42" in html
    assert "2026-06-02T09:00:00Z" in html


def test_report_renders_empty_state_without_findings():
    html = render_html_report([], [])

    assert "No findings." in html
    assert "No parse errors." in html
    assert "no findings" in html  # severity chip empty state


def test_report_escapes_untrusted_log_content():
    finding = sample_finding(username="<script>alert(1)</script>")
    error = ParseError(line_number=3, reason="invalid json", raw_line="<img src=x onerror=alert(1)>")
    html = render_html_report([finding], [error])

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "invalid json" in html


def test_report_truncates_long_raw_lines():
    error = ParseError(line_number=1, reason="invalid json", raw_line="x" * 500)
    html = render_html_report([], [error])

    assert "x" * 500 not in html
    assert "x" * 119 + "…" in html


def test_cli_html_flag_writes_report(tmp_path, capsys):
    log_file = tmp_path / "app.jsonl"
    records = []
    for minute in range(5):
        records.append(
            {
                "timestamp": f"2026-06-02T09:0{minute}:00Z",
                "event_type": "login_failure",
                "source_ip": "127.0.0.1",
                "username": "test-user",
            }
        )
    log_file.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    html_file = tmp_path / "reports" / "findings.html"

    exit_code = main(["--log-file", str(log_file), "--html", str(html_file)])

    assert exit_code == 0
    assert html_file.exists()
    html = html_file.read_text(encoding="utf-8")
    assert "AUTH-BRUTE-FORCE-001" in html
    captured = capsys.readouterr()
    assert "Wrote HTML report" in captured.err
    assert "AUTH-BRUTE-FORCE-001" in captured.out  # human output still printed
