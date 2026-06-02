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


@dataclass(frozen=True)
class LabSettings:
    mode: str
    log_file: Path
    secret_key: str


class JsonlLogger:
    """Append one structured JSON object per line for local detection work."""

    def __init__(self, log_file: Path):
        self.log_file = log_file
        self._lock = Lock()

    def write(self, event: dict[str, Any]) -> None:
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
        return render_template_string(LOGIN_TEMPLATE, mode=settings.mode, message=None)

    @app.post("/login")
    def login() -> Response | str:
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
        username = request.args.get("username", "test-user")
        return render_template_string(DASHBOARD_TEMPLATE, username=username, mode=settings.mode)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    return app


def load_settings(test_config: dict[str, Any] | None = None) -> LabSettings:
    test_config = test_config or {}
    mode = str(test_config.get("LAB_MODE") or os.environ.get("LAB_MODE", "insecure")).lower()
    if mode not in ALLOWED_MODES:
        raise ValueError(f"LAB_MODE must be one of: {', '.join(sorted(ALLOWED_MODES))}")

    default_log_file = Path(__file__).resolve().parents[2] / "logs" / "application.jsonl"
    log_file = Path(test_config.get("LAB_LOG_FILE") or os.environ.get("LAB_LOG_FILE", default_log_file))
    secret_key = str(test_config.get("SECRET_KEY") or os.environ.get("SECRET_KEY", "local-lab-dev-key"))
    return LabSettings(mode=mode, log_file=log_file, secret_key=secret_key)


def _valid_credentials(username: str, password: str, mode: str) -> bool:
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
    now = time.time()
    key = (source_ip, username)
    recent = [ts for ts in failure_tracker.get(key, []) if now - ts <= LOCKOUT_WINDOW_SECONDS]
    failure_tracker[key] = recent
    return len(recent) >= LOCKOUT_FAILURE_LIMIT


def _source_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()


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
    logger.write(
        {
            "event_type": event_type,
            "source_ip": source_ip or "127.0.0.1",
            "username": username or "anonymous",
            "user_agent": request.headers.get("User-Agent", ""),
            "request_path": request.path,
            "http_method": request.method,
            "status_code": status_code,
            "lab_mode": current_app.config["LAB_MODE"],
            "reason": reason,
            "session_id": None,
            "request_id": request_id,
            "success": success,
        }
    )


LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Local Lab Login</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 4rem auto; padding: 0 1rem; }
      form { display: grid; gap: 0.75rem; border: 1px solid #ccc; padding: 1rem; }
      label { display: grid; gap: 0.25rem; }
      input, button { font: inherit; padding: 0.5rem; }
      .warning { color: #7a2e00; }
      .message { color: #8a0000; }
    </style>
  </head>
  <body>
    <h1>Local Lab Login</h1>
    <p class="warning">Local educational lab only. Do not deploy publicly.</p>
    <p>Mode: <strong>{{ mode }}</strong></p>
    {% if message %}<p class="message">{{ message }}</p>{% endif %}
    <form method="post" action="/login">
      <label>
        Username
        <input name="username" autocomplete="username" required>
      </label>
      <label>
        Password
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>
"""


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Local Lab Dashboard</title>
  </head>
  <body>
    <h1>Local Lab Dashboard</h1>
    <p>Signed in as {{ username }} in {{ mode }} mode.</p>
    <p>This page is part of the local-only educational lab.</p>
  </body>
</html>
"""
