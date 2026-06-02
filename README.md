# OWASP Lab Detection Engine

OWASP Lab Detection Engine is a local cybersecurity learning lab that
combines a deliberately vulnerable web application with structured logging and
a Python-based detection engine.

The project is intended to demonstrate how common web application weaknesses can
be represented in application logs, parsed consistently, and mapped to
documented detection rules. It is designed for local education, portfolio work,
and defensive security practice.

## Safety Warning

This repository is for local educational use only.

The vulnerable application must not be deployed publicly, exposed to the
internet, or used as a target model for third-party systems. All examples,
payloads, logs, and detection rules in this project must target only the local
lab application.

## Planned Lab Components

- A configurable vulnerable web app with safe local-only OWASP-style scenarios
- Structured JSON or JSONL application logs
- A Python detection engine for parsing and evaluating login-flow log events
- Documented detection rules that explain expected signals and status
- Optional export formats for tools such as Wazuh or a local SIEM

## Intended Learning Goals

- Understand how vulnerable web application behavior appears in logs
- Practice writing structured logs that support detection engineering
- Build a small Python parser for JSONL security telemetry
- Translate application behavior into documented detection rules
- Compare vulnerable and secure implementation modes in a controlled lab
- Learn how defensive detections can be tested without targeting real systems

## Planned Roadmap

1. Project structure and documentation
2. Basic vulnerable login flow
3. Structured application logging
4. Python log parser
5. Detection rules for brute force, SQL injection-like input, XSS-like input,
   and broken access control
6. Docker Compose local lab
7. Optional Wazuh/SIEM export format

## Repository Structure

```text
.
|-- vulnerable-app/       # Local vulnerable web application
|-- detection-engine/     # Future Python detection engine
|-- logs/                 # Sample and generated JSONL logs
|-- docs/                 # Architecture, threat model, and detection rules
|-- tests/                # Pytest coverage for implemented behavior
|-- docker-compose.yml    # Local vulnerable-app orchestration
|-- AGENTS.md             # Guidance for future AI/code agents
|-- SECURITY.md           # Responsible local-use policy
```

## Portfolio Relevance

This project is intended to show practical defensive security engineering
skills without overclaiming production readiness. When implemented, it should
demonstrate:

- secure documentation of intentionally vulnerable examples
- application logging design for detection use cases
- Python log parsing and rule evaluation
- clear separation between vulnerable behavior, secure behavior, and detection
  logic
- local lab orchestration with Docker Compose
- professional security boundaries and responsible-use language

The current state is an initial documentation and structure foundation. The web
application includes a minimal local login flow, and the detection engine can
parse local JSONL logs and detect repeated login failures.

## Local App Usage

The vulnerable app is intended to run on `127.0.0.1:8080` only.

Start the local lab app:

```bash
docker compose up --build
```

Choose the mode with `LAB_MODE`:

```bash
LAB_MODE=insecure docker compose up --build
LAB_MODE=secure docker compose up --build
```

Supported modes:

- `insecure` - intentionally weak local lab behavior for observing logs
- `secure` - basic safer comparison behavior and simple login lockout

Structured application logs are written to:

```text
logs/application.jsonl
```

Current login telemetry schema:

| Field | Description |
| --- | --- |
| `timestamp` | UTC ISO-8601 event timestamp |
| `event_type` | One of `login_success`, `login_failure`, `account_lockout`, or `access_denied` |
| `source_ip` | Local/private client address, normally `127.0.0.1` |
| `username` | Fictional local lab username |
| `user_agent` | Client user-agent string, when provided |
| `request_path` | HTTP path that produced the event |
| `http_method` | HTTP method such as `POST` or `GET` |
| `status_code` | HTTP response status code |
| `lab_mode` | `insecure` or `secure` |
| `reason` | Short machine-readable reason for the event |
| `session_id` | Fake/local session identifier when available, otherwise `null` |

The current demo credentials are fictional local lab users only:

```text
test-user / lab-password
admin / admin-password
```

Run the current tests:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Run the detection engine against generated app logs:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

Current implemented detection rule:

- `AUTH-BRUTE-FORCE-001` - alerts on 5 or more `login_failure` events for the
  same `source_ip` and `username` within 5 minutes
