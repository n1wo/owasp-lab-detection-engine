<!-- Intro: Component map and data-flow explanation for the local lab architecture. -->

# Architecture

This document describes the local lab architecture. The vulnerable app has a
minimal login implementation plus local search, comment, admin-panel, and
server-side fetch scenarios, and a detection engine that parses JSONL logs for
brute-force, SQLi-like, XSS-like, broken-access-control, and SSRF pattern
detection.

## Components

### Vulnerable App

The vulnerable app is a local Flask web application with configurable
vulnerable and secure modes. The current implementation includes a login page,
a search page, a comment page, an admin panel guarded by a broken access
control check, a server-side fetch page, and structured logs for login
outcomes, suspicious input, admin access, and outbound requests.

### Structured Logs

The app writes JSONL events containing fields such as timestamp,
event type, source IP, username, user agent, request path, HTTP method, status
code, lab mode, reason, and session ID. Logs should use local/private example
values only.

Current telemetry schema:

| Field | Description |
| --- | --- |
| `timestamp` | UTC ISO-8601 event timestamp |
| `event_type` | `login_success`, `login_failure`, `account_lockout`, `suspicious_input`, `admin_access`, `outbound_request`, or `lab_mode_change` |
| `source_ip` | Local/private client address |
| `username` | Fictional local lab username |
| `user_agent` | Client user-agent string, when provided |
| `request_path` | HTTP path that produced the event |
| `http_method` | HTTP method such as `POST` or `GET` |
| `status_code` | HTTP response status code |
| `lab_mode` | `insecure` or `secure` |
| `reason` | Short machine-readable reason |
| `session_id` | Fake/local session identifier when available, otherwise `null` |
| `signal` | Suspicious-input signal such as `sql_injection_like_pattern` or `xss_like_pattern`, when present |
| `input_name` | Submitted field name for suspicious input, when present |
| `input_value` | Local lab input value for suspicious input, when present |

### Detection Engine

The Python detection engine reads local JSONL logs, normalizes events, applies
implemented detection rules, and emits local findings. Current rules are
`AUTH-BRUTE-FORCE-001`, `WEB-SQLI-PATTERN-001`, `WEB-XSS-PATTERN-001`,
`BAC-PRIV-ESC-001`, and `WEB-SSRF-INTERNAL-001`. The engine should focus on
defensive detection behavior rather than offensive instructions.

### Optional SIEM/Wazuh Export

Later milestones may add an export format suitable for importing findings into
Wazuh or another local SIEM-style tool.

## Data Flow

```mermaid
flowchart LR
    User["Local learner"] --> App["Vulnerable app<br>localhost only"]
    App --> Logs["Structured JSONL logs"]
    Logs --> Engine["Python detection engine"]
    Engine --> Findings["Local findings"]
    Engine -. optional .-> SIEM["Wazuh/SIEM export"]
```

## Local-Only Boundary

The architecture assumes a local lab environment. The vulnerable application
should bind to localhost or another private local interface and should not be
published as a public service.
