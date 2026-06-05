<!-- Intro: Component map and data-flow explanation for the local lab architecture. -->

# Architecture

This document describes the local lab architecture. The vulnerable app has a
minimal login implementation, and the detection engine currently parses JSONL
logs for brute-force login detection.

## Components

### Vulnerable App

The vulnerable app is a local Flask web application with configurable
vulnerable and secure modes. The current implementation includes a login page
and emits structured logs for login outcomes.

### Structured Logs

The app writes JSONL events containing fields such as timestamp,
event type, source IP, username, user agent, request path, HTTP method, status
code, lab mode, reason, and session ID. Logs should use local/private example
values only.

Current login telemetry schema:

| Field | Description |
| --- | --- |
| `timestamp` | UTC ISO-8601 event timestamp |
| `event_type` | `login_success`, `login_failure`, `account_lockout`, or `access_denied` |
| `source_ip` | Local/private client address |
| `username` | Fictional local lab username |
| `user_agent` | Client user-agent string, when provided |
| `request_path` | HTTP path that produced the event |
| `http_method` | HTTP method such as `POST` or `GET` |
| `status_code` | HTTP response status code |
| `lab_mode` | `insecure` or `secure` |
| `reason` | Short machine-readable reason |
| `session_id` | Fake/local session identifier when available, otherwise `null` |

### Detection Engine

The Python detection engine reads local JSONL logs, normalizes events, applies
the `AUTH-BRUTE-FORCE-001` detection rule, and emits local findings. It should
focus on defensive detection behavior rather than offensive instructions.

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
