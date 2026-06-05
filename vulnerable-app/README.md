<!-- Intro: Overview of the local Flask vulnerable app and its lab-only behavior. -->

# Vulnerable App

This folder contains the local-only vulnerable web application.

The app currently implements milestone 2: a minimal login page with
configuration-controlled insecure and secure modes plus structured JSONL
logging.

It must remain suitable for local lab use only and must not be deployed
publicly.

## Current Features

- Flask-based login page
- `LAB_MODE=insecure` for intentionally weak local lab behavior
- `LAB_MODE=secure` for generic failures and simple login lockout
- consistent JSONL login telemetry written to `logs/application.jsonl`
- localhost-only Docker Compose port binding

## Login Telemetry Schema

Each login-related JSONL event includes:

| Field | Description |
| --- | --- |
| `timestamp` | UTC ISO-8601 event timestamp |
| `event_type` | `login_success`, `login_failure`, `account_lockout`, or `access_denied` |
| `source_ip` | Local/private client address |
| `username` | Fictional local lab username |
| `user_agent` | Client user-agent string, when provided |
| `request_path` | HTTP path that produced the event |
| `http_method` | HTTP method such as `POST` |
| `status_code` | HTTP response status code |
| `lab_mode` | `insecure` or `secure` |
| `reason` | Short machine-readable reason |
| `session_id` | Fake/local session identifier when available, otherwise `null` |

## Local Commands

From the repository root:

```bash
docker compose up --build
```

Run in secure mode:

```bash
LAB_MODE=secure docker compose up --build
```

Run directly during development:

```bash
cd vulnerable-app
python -m vulnerable_app
```

## Local Lab Credentials

These credentials are fictional and only for this local lab:

```text
test-user / lab-password
admin / admin-password
```

## Boundary

The current vulnerable scenario is a brute-forceable login flow in insecure
mode. Future scenarios should keep vulnerable and secure behavior clearly
separated.
