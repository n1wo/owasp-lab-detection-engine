"""Flask routes, lab settings, and telemetry for the local vulnerable app."""

from __future__ import annotations

import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from flask import Flask, Response, current_app, redirect, render_template_string, request, url_for


VALID_USERS = {
    "test-user": "lab-password",
    "admin": "admin-password",
}

ALLOWED_MODES = {"insecure", "secure"}
LOCKOUT_FAILURE_LIMIT = 5
LOCKOUT_WINDOW_SECONDS = 300
SQLI_SIGNAL = "sql_injection_like_pattern"
SQLI_MARKERS = ("' or '", '" or "', "--", "/*", "*/", " union ", " select ")


@dataclass(frozen=True)
class LabSettings:
    mode: str
    log_file: Path
    secret_key: str


class JsonlLogger:
    """Append one structured JSON object per line for local detection work."""

    def __init__(self, log_file: Path):
        """Remember the target JSONL file and create a lock for safe appends."""

        self.log_file = log_file
        self._lock = Lock()

    def write(self, event: dict[str, Any]) -> None:
        """Append one enriched security telemetry event to the JSONL log file."""

        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "app": "vulnerable-app",
            "environment": "local-lab",
            **event,
        }
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the local lab app.

    `LAB_MODE=insecure` intentionally keeps weak login behavior for the lab.
    `LAB_MODE=secure` provides a basic comparison mode, not production auth.
    """

    settings = load_settings(test_config)
    app = Flask(__name__)
    app.config.update(
        LAB_MODE=settings.mode,
        LAB_LOG_FILE=str(settings.log_file),
        SECRET_KEY=settings.secret_key,
    )

    logger = JsonlLogger(settings.log_file)
    failure_tracker: dict[tuple[str, str], list[float]] = {}

    @app.get("/")
    def index() -> Response | str:
        """Render the login form for the current lab mode."""

        return render_template_string(LOGIN_TEMPLATE, mode=settings.mode, message=None)

    @app.post("/login")
    def login() -> Response | str:
        """Process a login attempt, emit telemetry, and enforce mode behavior."""

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        source_ip = _source_ip()
        request_id = str(uuid.uuid4())

        if settings.mode == "secure" and _is_locked(failure_tracker, source_ip, username):
            _log_login_event(
                logger,
                event_type="account_lockout",
                request_id=request_id,
                source_ip=source_ip,
                username=username,
                status_code=429,
                success=False,
                reason="too_many_failures",
            )
            return (
                render_template_string(
                    LOGIN_TEMPLATE,
                    mode=settings.mode,
                    message="Too many failed attempts. Try again later.",
                ),
                429,
            )

        is_valid = _valid_credentials(username, password, settings.mode)
        if is_valid:
            failure_tracker.pop((source_ip, username), None)
            _log_login_event(
                logger,
                event_type="login_success",
                request_id=request_id,
                source_ip=source_ip,
                username=username,
                status_code=302,
                success=True,
                reason="valid_credentials",
            )
            return redirect(url_for("dashboard", username=username))

        if settings.mode == "secure":
            _record_failure(failure_tracker, source_ip, username)
            message = "Invalid username or password."
            reason = "invalid_credentials"
        else:
            message, reason = _insecure_failure_message(username)

        _log_login_event(
            logger,
            event_type="login_failure",
            request_id=request_id,
            source_ip=source_ip,
            username=username,
            status_code=401,
            success=False,
            reason=reason,
        )
        return render_template_string(LOGIN_TEMPLATE, mode=settings.mode, message=message), 401

    @app.get("/dashboard")
    def dashboard() -> str:
        """Render a simple local dashboard after a successful lab login."""

        username = request.args.get("username", "test-user")
        return render_template_string(DASHBOARD_TEMPLATE, username=username, mode=settings.mode)

    @app.get("/search")
    def search() -> Response | str:
        """Render a local search page and log SQLi-like input when observed."""

        query = request.args.get("q", "").strip()
        source_ip = _source_ip()
        request_id = str(uuid.uuid4())
        signal = _sqli_signal(query)
        status_code = 200
        message = None
        results: list[str] = []

        if query and signal:
            if settings.mode == "secure":
                status_code = 400
                message = "Search input was rejected."
                reason = "rejected_suspicious_input"
            else:
                message = "Insecure mode accepted suspicious-looking search input."
                results = [
                    "Local lab result: test-user profile",
                    "Local lab result: admin profile",
                    "Local lab result: demo account notes",
                ]
                reason = "accepted_suspicious_input"

            _log_suspicious_input_event(
                logger,
                request_id=request_id,
                source_ip=source_ip,
                input_value=query,
                status_code=status_code,
                success=settings.mode == "insecure",
                reason=reason,
                signal=signal,
            )
        elif query:
            results = [f"Local lab result for {query}"]

        rendered = render_template_string(
            SEARCH_TEMPLATE,
            mode=settings.mode,
            query=query,
            message=message,
            results=results,
        )
        if status_code != 200:
            return rendered, status_code
        return rendered

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return a small readiness response with the configured lab mode."""

        return {"status": "ok", "mode": settings.mode}

    return app


def load_settings(test_config: dict[str, Any] | None = None) -> LabSettings:
    """Load lab settings from tests or environment variables."""

    test_config = test_config or {}
    mode = str(test_config.get("LAB_MODE") or os.environ.get("LAB_MODE", "insecure")).lower()
    if mode not in ALLOWED_MODES:
        raise ValueError(f"LAB_MODE must be one of: {', '.join(sorted(ALLOWED_MODES))}")

    default_log_file = Path(__file__).resolve().parents[2] / "logs" / "application.jsonl"
    log_file = Path(test_config.get("LAB_LOG_FILE") or os.environ.get("LAB_LOG_FILE", default_log_file))
    secret_key = str(test_config.get("SECRET_KEY") or os.environ.get("SECRET_KEY", "local-lab-dev-key"))
    return LabSettings(mode=mode, log_file=log_file, secret_key=secret_key)


def _valid_credentials(username: str, password: str, mode: str) -> bool:
    """Check fictional lab credentials using the comparison for the active mode."""

    expected = VALID_USERS.get(username)
    if expected is None:
        if mode == "secure":
            # Keep secure-mode timing less dependent on whether the user exists.
            hmac.compare_digest(password, "not-a-real-password")
        return False
    if mode == "secure":
        return hmac.compare_digest(password, expected)
    # Intentional lab behavior: insecure mode uses direct comparison.
    return password == expected


def _insecure_failure_message(username: str) -> tuple[str, str]:
    """Return intentionally over-specific messages for the vulnerable mode."""

    if username not in VALID_USERS:
        return "Unknown user.", "unknown_user"
    return "Incorrect password.", "bad_password"


def _record_failure(
    failure_tracker: dict[tuple[str, str], list[float]],
    source_ip: str,
    username: str,
) -> None:
    """Store a recent failed login timestamp for secure-mode lockout checks."""

    now = time.time()
    key = (source_ip, username)
    recent = [ts for ts in failure_tracker.get(key, []) if now - ts <= LOCKOUT_WINDOW_SECONDS]
    recent.append(now)
    failure_tracker[key] = recent


def _is_locked(
    failure_tracker: dict[tuple[str, str], list[float]],
    source_ip: str,
    username: str,
) -> bool:
    """Return whether a source/user pair has reached the lockout threshold."""

    now = time.time()
    key = (source_ip, username)
    recent = [ts for ts in failure_tracker.get(key, []) if now - ts <= LOCKOUT_WINDOW_SECONDS]
    failure_tracker[key] = recent
    return len(recent) >= LOCKOUT_FAILURE_LIMIT


def _source_ip() -> str:
    """Resolve the apparent client IP from the request for local telemetry."""

    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()


def _sqli_signal(value: str) -> str | None:
    """Return the SQLi-like signal name when local demo input matches markers."""

    normalized = f" {value.lower()} "
    if any(marker in normalized for marker in SQLI_MARKERS):
        return SQLI_SIGNAL
    return None


def _common_event_fields(status_code: int, request_id: str) -> dict[str, Any]:
    """Build request metadata shared by all local lab telemetry events."""

    return {
        "user_agent": request.headers.get("User-Agent", ""),
        "request_path": request.path,
        "http_method": request.method,
        "status_code": status_code,
        "lab_mode": current_app.config["LAB_MODE"],
        "request_id": request_id,
    }


def _log_login_event(
    logger: JsonlLogger,
    *,
    event_type: str,
    request_id: str,
    source_ip: str,
    username: str,
    status_code: int,
    success: bool,
    reason: str,
) -> None:
    """Write one structured login event with common request metadata."""

    logger.write(
        {
            "event_type": event_type,
            "source_ip": source_ip or "127.0.0.1",
            "username": username or "anonymous",
            **_common_event_fields(status_code, request_id),
            "reason": reason,
            "session_id": None,
            "success": success,
        }
    )


def _log_suspicious_input_event(
    logger: JsonlLogger,
    *,
    request_id: str,
    source_ip: str,
    input_value: str,
    status_code: int,
    success: bool,
    reason: str,
    signal: str,
) -> None:
    """Write one structured suspicious-input event for local detection rules."""

    logger.write(
        {
            "event_type": "suspicious_input",
            "source_ip": source_ip or "127.0.0.1",
            "username": "anonymous",
            **_common_event_fields(status_code, request_id),
            "reason": reason,
            "signal": signal,
            "input_name": "q",
            "input_value": input_value,
            "success": success,
        }
    )


BASE_STYLES = """
      :root {
        --bg: #0b1120;
        --bg-glow-1: rgba(34, 211, 238, 0.08);
        --bg-glow-2: rgba(99, 102, 241, 0.10);
        --surface: #111a2e;
        --surface-2: #16213a;
        --border: #243352;
        --border-strong: #31436b;
        --text: #e2e8f0;
        --text-muted: #8fa3c4;
        --text-faint: #64748b;
        --accent: #22d3ee;
        --accent-strong: #06b6d4;
        --accent-contrast: #06222b;
        --danger-bg: rgba(248, 113, 113, 0.10);
        --danger-border: rgba(248, 113, 113, 0.35);
        --danger-text: #fca5a5;
        --warn-bg: rgba(251, 191, 36, 0.08);
        --warn-border: rgba(251, 191, 36, 0.30);
        --warn-text: #fcd34d;
        --ok: #34d399;
        --mono: "SF Mono", "Cascadia Code", "JetBrains Mono", Consolas, monospace;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem 1rem;
        font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
        color: var(--text);
        background:
          radial-gradient(60rem 30rem at 15% 0%, var(--bg-glow-2), transparent 60%),
          radial-gradient(50rem 28rem at 85% 100%, var(--bg-glow-1), transparent 60%),
          var(--bg);
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        margin-bottom: 1.5rem;
        font-family: var(--mono);
        font-size: 0.95rem;
        letter-spacing: 0.08em;
        color: var(--text-muted);
        text-transform: uppercase;
      }
      .brand .dot {
        width: 0.55rem;
        height: 0.55rem;
        border-radius: 50%;
        background: var(--accent);
        box-shadow: 0 0 10px var(--accent);
      }
      .card {
        width: 100%;
        max-width: 26rem;
        background: linear-gradient(180deg, var(--surface-2), var(--surface));
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 2rem;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      }
      h1 { margin: 0 0 0.35rem; font-size: 1.35rem; font-weight: 600; }
      .subtitle { margin: 0 0 1.4rem; color: var(--text-muted); font-size: 0.9rem; }
      .badges { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.4rem; }
      .badge {
        font-family: var(--mono);
        font-size: 0.72rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 0.3rem 0.6rem;
        border-radius: 999px;
        border: 1px solid var(--border-strong);
        color: var(--text-muted);
        background: rgba(255, 255, 255, 0.02);
      }
      .badge.mode-insecure { color: var(--warn-text); border-color: var(--warn-border); background: var(--warn-bg); }
      .badge.mode-secure { color: var(--ok); border-color: rgba(52, 211, 153, 0.35); background: rgba(52, 211, 153, 0.08); }
      .notice {
        display: flex;
        gap: 0.6rem;
        align-items: flex-start;
        font-size: 0.83rem;
        line-height: 1.45;
        border-radius: 10px;
        padding: 0.7rem 0.85rem;
        margin-bottom: 1.2rem;
      }
      .notice.warning { background: var(--warn-bg); border: 1px solid var(--warn-border); color: var(--warn-text); }
      .notice.error { background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger-text); }
      label { display: grid; gap: 0.4rem; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; }
      input {
        font: inherit;
        color: var(--text);
        background: var(--bg);
        border: 1px solid var(--border-strong);
        border-radius: 8px;
        padding: 0.65rem 0.8rem;
        outline: none;
        transition: border-color 0.15s, box-shadow 0.15s;
      }
      input:focus { border-color: var(--accent-strong); box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.18); }
      button {
        width: 100%;
        font: inherit;
        font-weight: 600;
        color: var(--accent-contrast);
        background: linear-gradient(180deg, var(--accent), var(--accent-strong));
        border: none;
        border-radius: 8px;
        padding: 0.7rem;
        cursor: pointer;
        margin-top: 0.4rem;
        transition: filter 0.15s, transform 0.05s;
      }
      button:hover { filter: brightness(1.1); }
      button:active { transform: translateY(1px); }
      .footer {
        margin-top: 1.5rem;
        font-family: var(--mono);
        font-size: 0.72rem;
        color: var(--text-faint);
        letter-spacing: 0.05em;
      }
      .meta { font-family: var(--mono); font-size: 0.8rem; color: var(--text-muted); }
      .meta strong { color: var(--accent); font-weight: 600; }
"""


LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; Sign In</title>
    <style>{styles}</style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card">
      <h1>Sign in</h1>
      <p class="subtitle">Authentication telemetry lab &mdash; login events are logged as JSONL.</p>
      <div class="badges">
        <span class="badge">local-lab</span>
        <span class="badge mode-{{ mode }}">mode: {{ mode }}</span>
      </div>
      <div class="notice warning">&#9888;&#65039;&nbsp; Local educational lab only. Do not deploy publicly.</div>
      {% if message %}<div class="notice error">&#9940;&nbsp; {{ message }}</div>{% endif %}
      <form method="post" action="/login">
        <label>
          Username
          <input name="username" autocomplete="username" placeholder="test-user" required>
        </label>
        <label>
          Password
          <input name="password" type="password" autocomplete="current-password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
        </label>
        <button type="submit">Sign in</button>
      </form>
    </div>
    <div class="footer">AUTH-BRUTE-FORCE-001 &middot; logs/application.jsonl</div>
  </body>
</html>
""".replace("{styles}", BASE_STYLES)


SEARCH_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; Search</title>
    <style>{styles}
      .results { margin: 1.2rem 0 0; padding: 0; list-style: none; }
      .results li {
        font-family: var(--mono);
        font-size: 0.85rem;
        color: var(--text-muted);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 0.6rem 0.8rem;
        margin-bottom: 0.5rem;
        background: rgba(255, 255, 255, 0.02);
      }
      h2 { margin: 1.4rem 0 0; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
    </style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card">
      <h1>Search</h1>
      <p class="subtitle">SQLi telemetry lab &mdash; suspicious input is logged as JSONL.</p>
      <div class="badges">
        <span class="badge">local-lab</span>
        <span class="badge mode-{{ mode }}">mode: {{ mode }}</span>
      </div>
      <div class="notice warning">&#9888;&#65039;&nbsp; Local educational lab only. Do not deploy publicly.</div>
      {% if message %}<div class="notice error">&#9940;&nbsp; {{ message }}</div>{% endif %}
      <form method="get" action="/search">
        <label>
          Search query
          <input name="q" value="{{ query }}" autocomplete="off" placeholder="e.g. demo account">
        </label>
        <button type="submit">Search</button>
      </form>
      {% if results %}
        <h2>Results</h2>
        <ul class="results">
          {% for result in results %}<li>{{ result }}</li>{% endfor %}
        </ul>
      {% endif %}
    </div>
    <div class="footer">WEB-SQLI-PATTERN-001 &middot; logs/application.jsonl</div>
  </body>
</html>
""".replace("{styles}", BASE_STYLES)


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; Dashboard</title>
    <style>{styles}</style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card">
      <h1>Dashboard</h1>
      <p class="subtitle">Signed in as {{ username }} in {{ mode }} mode.</p>
      <div class="badges">
        <span class="badge">local-lab</span>
        <span class="badge mode-{{ mode }}">mode: {{ mode }}</span>
      </div>
      <p class="meta">session: <strong>{{ username }}</strong></p>
      <div class="notice warning">&#9888;&#65039;&nbsp; This page is part of the local-only educational lab.</div>
      <form method="get" action="/">
        <button type="submit">Sign out</button>
      </form>
    </div>
    <div class="footer">AUTH-BRUTE-FORCE-001 &middot; logs/application.jsonl</div>
  </body>
</html>
""".replace("{styles}", BASE_STYLES)
