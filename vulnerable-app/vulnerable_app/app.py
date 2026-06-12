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

from flask import Flask, Response, current_app, redirect, render_template_string, request, send_file, url_for


VALID_USERS = {
    "test-user": "lab-password",
    "admin": "admin-password",
}

ALLOWED_MODES = {"insecure", "secure"}
LOCKOUT_FAILURE_LIMIT = 5
LOCKOUT_WINDOW_SECONDS = 300
SQLI_SIGNAL = "sql_injection_like_pattern"
SQLI_MARKERS = ("' or '", '" or "', "--", "/*", "*/", " union ", " select ")
XSS_SIGNAL = "xss_like_pattern"
XSS_MARKERS = ("<script", "javascript:", "onerror=", "onload=", "<img", "<svg")


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

    def _mode() -> str:
        """Return the currently active lab mode (toggleable at runtime)."""

        return app.config["LAB_MODE"]

    @app.get("/")
    def index() -> Response | str:
        """Render the login form for the current lab mode."""

        return render_template_string(LOGIN_TEMPLATE, mode=_mode(), message=None)

    @app.post("/login")
    def login() -> Response | str:
        """Process a login attempt, emit telemetry, and enforce mode behavior."""

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        source_ip = _source_ip()
        request_id = str(uuid.uuid4())

        if _mode() == "secure" and _is_locked(failure_tracker, source_ip, username):
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
                    mode=_mode(),
                    message="Too many failed attempts. Try again later.",
                ),
                429,
            )

        is_valid = _valid_credentials(username, password, _mode())
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

        if _mode() == "secure":
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
        return render_template_string(LOGIN_TEMPLATE, mode=_mode(), message=message), 401

    @app.get("/dashboard")
    def dashboard() -> str:
        """Render a simple local dashboard after a successful lab login."""

        username = request.args.get("username", "test-user")
        return render_template_string(DASHBOARD_TEMPLATE, username=username, mode=_mode())

    @app.post("/lab/mode")
    def toggle_mode() -> Response:
        """Toggle the runtime lab mode between insecure and secure."""

        previous = _mode()
        new_mode = "secure" if previous == "insecure" else "insecure"
        app.config["LAB_MODE"] = new_mode

        logger.write(
            {
                "event_type": "lab_mode_change",
                "source_ip": _source_ip(),
                "username": "anonymous",
                **_common_event_fields(302, str(uuid.uuid4())),
                "reason": f"lab mode changed from {previous} to {new_mode}",
                "success": True,
            }
        )

        next_path = request.form.get("next", "/")
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/"
        return redirect(next_path)

    @app.get("/soc")
    def soc() -> Response | str:
        """Serve the latest generated report, or live SOC alerts from telemetry."""

        report_file = settings.log_file.resolve().parent / "findings.html"
        if report_file.is_file():
            return send_file(report_file, mimetype="text/html")
        alerts = _soc_alerts_from_log(settings.log_file)
        return render_template_string(
            SOC_LIVE_TEMPLATE,
            mode=_mode(),
            log_file=str(settings.log_file),
            report_file=str(report_file),
            alerts=alerts,
        )

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
            if _mode() == "secure":
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
                input_name="q",
                input_value=query,
                status_code=status_code,
                success=_mode() == "insecure",
                reason=reason,
                signal=signal,
            )
        elif query:
            results = [f"Local lab result for {query}"]

        rendered = render_template_string(
            SEARCH_TEMPLATE,
            mode=_mode(),
            query=query,
            message=message,
            results=results,
        )
        if status_code != 200:
            return rendered, status_code
        return rendered

    @app.route("/comment", methods=["GET", "POST"])
    def comment() -> Response | str:
        """Render a local comment page and log XSS-like input when observed."""

        comment_text = request.form.get("comment", "").strip() if request.method == "POST" else ""
        source_ip = _source_ip()
        request_id = str(uuid.uuid4())
        signal = _xss_signal(comment_text)
        status_code = 200
        message = None
        rendered_comment = ""

        if comment_text and signal:
            if _mode() == "secure":
                status_code = 400
                message = "Comment input was rejected."
                reason = "rejected_suspicious_input"
            else:
                message = "Insecure mode rendered suspicious-looking comment input."
                rendered_comment = comment_text
                reason = "rendered_suspicious_input"

            _log_suspicious_input_event(
                logger,
                request_id=request_id,
                source_ip=source_ip,
                input_name="comment",
                input_value=comment_text,
                status_code=status_code,
                success=_mode() == "insecure",
                reason=reason,
                signal=signal,
            )
        elif comment_text:
            rendered_comment = comment_text

        rendered = render_template_string(
            COMMENT_TEMPLATE,
            mode=_mode(),
            comment=comment_text,
            rendered_comment=rendered_comment,
            render_comment_as_html=_mode() == "insecure" and bool(signal),
            message=message,
        )
        if status_code != 200:
            return rendered, status_code
        return rendered

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return a small readiness response with the configured lab mode."""

        return {"status": "ok", "mode": _mode()}

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


def _xss_signal(value: str) -> str | None:
    """Return the XSS-like signal name when local demo input matches markers."""

    normalized = value.lower()
    if any(marker in normalized for marker in XSS_MARKERS):
        return XSS_SIGNAL
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
    input_name: str,
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
            "input_name": input_name,
            "input_value": input_value,
            "success": success,
        }
    )


def _soc_alerts_from_log(log_file: Path, limit: int = 25) -> list[dict[str, Any]]:
    """Build SOC console alerts directly from local app telemetry."""

    if not log_file.is_file():
        return []

    alerts: list[dict[str, Any]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert = _soc_alert_from_event(event)
        if alert is not None:
            alerts.append(alert)

    return list(reversed(alerts[-limit:]))


def _soc_alert_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Return a display alert for one noteworthy local telemetry event."""

    event_type = event.get("event_type")
    reason = event.get("reason")
    signal = event.get("signal")

    if event_type == "login_failure" and reason == "unknown_user":
        return _soc_alert(
            event,
            severity="Medium",
            title="Unknown username login attempt",
            rule="AUTH-UNKNOWN-USER-LOCAL",
            detail=f"Login attempted for unknown lab username {event.get('username', 'anonymous')!r}.",
        )
    if event_type == "login_failure":
        return _soc_alert(
            event,
            severity="Low",
            title="Failed login attempt",
            rule="AUTH-LOGIN-FAILURE-LOCAL",
            detail=f"Login failed for lab username {event.get('username', 'anonymous')!r}.",
        )
    if event_type == "account_lockout":
        return _soc_alert(
            event,
            severity="High",
            title="Account lockout triggered",
            rule="AUTH-LOCKOUT-LOCAL",
            detail=f"Too many failed attempts for lab username {event.get('username', 'anonymous')!r}.",
        )
    if event_type == "suspicious_input":
        label = "SQLi-like" if signal == SQLI_SIGNAL else "XSS-like" if signal == XSS_SIGNAL else "Suspicious"
        return _soc_alert(
            event,
            severity="Medium",
            title=f"{label} input observed",
            rule=str(signal or "SUSPICIOUS-INPUT-LOCAL"),
            detail=f"Suspicious input submitted to {event.get('request_path', 'unknown path')}.",
        )
    return None


def _soc_alert(
    event: dict[str, Any],
    *,
    severity: str,
    title: str,
    rule: str,
    detail: str,
) -> dict[str, Any]:
    """Normalize one SOC alert for template rendering."""

    return {
        "severity": severity,
        "title": title,
        "rule": rule,
        "detail": detail,
        "timestamp": event.get("timestamp", "unknown"),
        "source_ip": event.get("source_ip", "unknown"),
        "username": event.get("username", "anonymous"),
        "path": event.get("request_path", "unknown"),
        "reason": event.get("reason", "unknown"),
    }


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


NAV_SNIPPET = """
<nav class="labnav" id="labnav" aria-label="Lab console">
  <div class="labnav-panel">
    <div class="labnav-title">Lab Console</div>
    <div class="labnav-group">Scenarios</div>
    <a href="/">Brute force &middot; Login</a>
    <a href="/search">SQL injection &middot; Search</a>
    <a href="/comment">XSS &middot; Comment</a>
    <a href="/dashboard">Admin panel</a>
    <div class="labnav-group">Detection</div>
    <a href="/soc">SOC &middot; Findings report</a>
    <div class="labnav-group">Vulnerabilities</div>
    <form method="post" action="/lab/mode">
      <input type="hidden" name="next" value="{{ request.path }}">
      <button type="submit" class="labnav-switch state-{{ mode }}"
              title="Toggle between insecure and secure mode">
        <span class="labnav-switch-track"><span class="labnav-switch-dot"></span></span>
        <span class="labnav-switch-text">
          {% if mode == 'insecure' %}vulnerable: on{% else %}vulnerable: off{% endif %}
        </span>
      </button>
    </form>
    <div class="labnav-foot">mode: {{ mode }}</div>
  </div>
  <button class="labnav-tab" type="button" aria-controls="labnav" aria-expanded="false"
          onclick="var n=document.getElementById('labnav');n.classList.toggle('open');this.setAttribute('aria-expanded',n.classList.contains('open'));">
    <span class="labnav-tab-icon">&#9776;</span>
    <span class="labnav-tab-text">lab</span>
  </button>
</nav>
<style>
  .labnav {
    position: fixed; top: 50%; right: 0; transform: translateY(-50%);
    z-index: 1000; display: flex; align-items: center;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  .labnav-tab {
    width: auto; margin: 0; display: flex; flex-direction: column; align-items: center;
    gap: 0.3rem; padding: 0.7rem 0.55rem;
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    color: var(--text-muted); border: 1px solid var(--border); border-right: none;
    border-radius: 10px 0 0 10px; cursor: pointer;
    box-shadow: -8px 0 24px rgba(0, 0, 0, 0.35);
    transition: color 0.15s;
  }
  .labnav-tab:hover { color: var(--accent); filter: none; }
  .labnav-tab-icon { font-size: 0.95rem; line-height: 1; }
  .labnav-tab-text {
    font-family: var(--mono); font-size: 0.62rem; letter-spacing: 0.18em;
    text-transform: uppercase; writing-mode: vertical-rl;
  }
  .labnav-panel {
    width: 15.5rem; margin-right: -0.5rem; padding: 1.1rem 1.2rem;
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    border: 1px solid var(--border); border-radius: 14px;
    box-shadow: -16px 8px 40px rgba(0, 0, 0, 0.5);
    opacity: 0; visibility: hidden; transform: translateX(1rem);
    transition: opacity 0.18s ease, transform 0.18s ease, visibility 0.18s;
  }
  .labnav.open .labnav-panel { opacity: 1; visibility: visible; transform: translateX(-0.6rem); }
  .labnav-title {
    font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.12em;
    text-transform: uppercase; color: var(--accent); margin-bottom: 0.8rem;
  }
  .labnav-group {
    font-size: 0.62rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-faint); margin: 0.9rem 0 0.35rem;
  }
  .labnav-panel a {
    display: block; padding: 0.45rem 0.6rem; border-radius: 8px;
    color: var(--text-muted); text-decoration: none; font-size: 0.85rem;
    transition: background 0.12s, color 0.12s;
  }
  .labnav-panel a:hover { background: rgba(34, 211, 238, 0.08); color: var(--text); }
  .labnav-panel a.active { background: rgba(34, 211, 238, 0.12); color: var(--accent); }
  .labnav-panel form { margin: 0; }
  .labnav-switch {
    width: 100%; margin: 0; display: flex; align-items: center; gap: 0.6rem;
    padding: 0.5rem 0.6rem; background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-strong); border-radius: 8px;
    color: var(--text-muted); cursor: pointer; font-size: 0.8rem; font-weight: 600;
  }
  .labnav-switch:hover { filter: brightness(1.15); transform: none; }
  .labnav-switch-track {
    flex: none; width: 2rem; height: 1.05rem; border-radius: 999px;
    background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-strong);
    position: relative; transition: background 0.15s;
  }
  .labnav-switch-dot {
    position: absolute; top: 1px; width: 0.85rem; height: 0.85rem; border-radius: 50%;
    transition: left 0.15s, background 0.15s;
  }
  .labnav-switch.state-insecure .labnav-switch-track { background: rgba(251, 191, 36, 0.18); }
  .labnav-switch.state-insecure .labnav-switch-dot { left: calc(100% - 0.95rem); background: var(--warn-text); }
  .labnav-switch.state-insecure .labnav-switch-text { color: var(--warn-text); }
  .labnav-switch.state-secure .labnav-switch-dot { left: 1px; background: var(--ok); }
  .labnav-switch.state-secure .labnav-switch-text { color: var(--ok); }
  .labnav-switch-text { font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.06em; text-transform: uppercase; }
  .labnav-foot {
    margin-top: 0.9rem; font-family: var(--mono); font-size: 0.65rem;
    letter-spacing: 0.06em; color: var(--text-faint);
  }
</style>
<script>
  (function () {
    var path = window.location.pathname;
    document.querySelectorAll("#labnav .labnav-panel a").forEach(function (link) {
      if (link.getAttribute("href") === path) { link.classList.add("active"); }
    });
  })();
</script>
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
    {nav}
  </body>
</html>
""".replace("{styles}", BASE_STYLES).replace("{nav}", NAV_SNIPPET)


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
    {nav}
  </body>
</html>
""".replace("{styles}", BASE_STYLES).replace("{nav}", NAV_SNIPPET)


COMMENT_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; Comment</title>
    <style>{styles}
      .comment-preview {
        margin-top: 1.2rem;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 0.8rem;
        color: var(--text-muted);
        background: rgba(255, 255, 255, 0.02);
        overflow-wrap: anywhere;
      }
      textarea {
        min-height: 7rem;
        resize: vertical;
        font: inherit;
        color: var(--text);
        background: var(--bg);
        border: 1px solid var(--border-strong);
        border-radius: 8px;
        padding: 0.65rem 0.8rem;
        outline: none;
        transition: border-color 0.15s, box-shadow 0.15s;
      }
      textarea:focus { border-color: var(--accent-strong); box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.18); }
      h2 { margin: 1.4rem 0 0; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
    </style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card">
      <h1>Comment</h1>
      <p class="subtitle">XSS telemetry lab &mdash; suspicious comment input is logged as JSONL.</p>
      <div class="badges">
        <span class="badge">local-lab</span>
        <span class="badge mode-{{ mode }}">mode: {{ mode }}</span>
      </div>
      <div class="notice warning">&#9888;&#65039;&nbsp; Local educational lab only. Do not deploy publicly.</div>
      {% if message %}<div class="notice error">&#9940;&nbsp; {{ message }}</div>{% endif %}
      <form method="post" action="/comment">
        <label>
          Comment
          <textarea name="comment" autocomplete="off" placeholder="Share a local lab note">{{ comment }}</textarea>
        </label>
        <button type="submit">Post comment</button>
      </form>
      {% if rendered_comment %}
        <h2>Preview</h2>
        <div class="comment-preview">
          {% if render_comment_as_html %}{{ rendered_comment|safe }}{% else %}{{ rendered_comment }}{% endif %}
        </div>
      {% endif %}
    </div>
    <div class="footer">WEB-XSS-PATTERN-001 &middot; logs/application.jsonl</div>
    {nav}
  </body>
</html>
""".replace("{styles}", BASE_STYLES).replace("{nav}", NAV_SNIPPET)


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; Admin Panel</title>
    <style>{styles}</style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card">
      <h1>Admin panel</h1>
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
    {nav}
  </body>
</html>
""".replace("{styles}", BASE_STYLES).replace("{nav}", NAV_SNIPPET)


SOC_LIVE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OWASP Lab &middot; SOC</title>
    <style>{styles}
      body { justify-content: flex-start; }
      .soc-card { max-width: 54rem; }
      .soc-grid { display: grid; gap: 0.8rem; margin-top: 1.2rem; }
      .alert {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 0.9rem 1rem;
        background: rgba(255, 255, 255, 0.02);
      }
      .alert-head {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: flex-start;
        margin-bottom: 0.5rem;
      }
      .alert-title { margin: 0; font-size: 0.95rem; font-weight: 600; }
      .alert-detail { margin: 0 0 0.65rem; color: var(--text-muted); font-size: 0.86rem; line-height: 1.45; }
      .alert-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 0.45rem;
        font-family: var(--mono);
        font-size: 0.72rem;
        color: var(--text-faint);
      }
      .chip {
        display: inline-block;
        font-family: var(--mono);
        font-size: 0.7rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 0.25rem 0.55rem;
        border-radius: 999px;
        border: 1px solid var(--border-strong);
        color: var(--text-muted);
      }
      .chip.sev-high { color: var(--danger-text); border-color: var(--danger-border); background: var(--danger-bg); }
      .chip.sev-medium { color: var(--warn-text); border-color: var(--warn-border); background: var(--warn-bg); }
      .chip.sev-low { color: #93c5fd; border-color: rgba(96, 165, 250, 0.35); background: rgba(96, 165, 250, 0.08); }
      .empty {
        border: 1px dashed var(--border-strong);
        border-radius: 10px;
        padding: 1rem;
        color: var(--text-muted);
        background: rgba(255, 255, 255, 0.02);
      }
    </style>
  </head>
  <body>
    <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
    <div class="card soc-card">
      <h1>Live SOC Alerts</h1>
      <p class="subtitle">Alerts are generated directly from local JSONL telemetry.</p>
      <div class="badges">
        <span class="badge">local-lab</span>
        <span class="badge mode-{{ mode }}">mode: {{ mode }}</span>
        <span class="badge">{{ alerts|length }} alerts</span>
      </div>
      <div class="notice warning">&#9888;&#65039;&nbsp; Live view reads: {{ log_file }}</div>
      {% if alerts %}
        <div class="soc-grid">
          {% for alert in alerts %}
            <article class="alert">
              <div class="alert-head">
                <h2 class="alert-title">{{ alert.title }}</h2>
                <span class="chip sev-{{ alert.severity|lower }}">{{ alert.severity }}</span>
              </div>
              <p class="alert-detail">{{ alert.detail }}</p>
              <div class="alert-meta">
                <span>{{ alert.rule }}</span>
                <span>{{ alert.timestamp }}</span>
                <span>source={{ alert.source_ip }}</span>
                <span>user={{ alert.username }}</span>
                <span>path={{ alert.path }}</span>
                <span>reason={{ alert.reason }}</span>
              </div>
            </article>
          {% endfor %}
        </div>
      {% else %}
        <div class="empty">No live alerts yet. Try a failed login, suspicious search, or XSS-style comment in the local lab.</div>
      {% endif %}
      <p class="footer">Generated HTML report path: {{ report_file }}</p>
    </div>
    {nav}
  </body>
</html>
""".replace("{styles}", BASE_STYLES).replace("{nav}", NAV_SNIPPET)
