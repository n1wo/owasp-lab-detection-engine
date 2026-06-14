<!-- Intro: Overview of the local Flask vulnerable app and its lab-only behavior. -->

# Vulnerable App

This folder contains the local-only vulnerable web application.

The app currently implements twelve OWASP-oriented scenarios spanning login,
search, comment, access control, SSRF, debug exposure, registration, admin
audit, profile import, checkout, exception handling, and component sync, each
with configuration-controlled insecure and secure modes plus structured JSONL
logging.

It must remain suitable for local lab use only and must not be deployed
publicly.

## Current Features

- Flask-based login page
- Flask-based search page
- Flask-based comment page
- admin panel at `/dashboard` with an intentionally broken access control check
- server-side fetch page at `/fetch` for SSRF-style local learning
- debug endpoint at `/debug` that leaks config in insecure mode (misconfiguration)
- registration page at `/register` with weak vs salted password hashing
- sensitive admin action at `/admin/role` with mode-dependent audit logging
- profile import page at `/profile/import` with unsafe serialized object trust
- checkout page at `/checkout` with client-controlled price abuse
- entitlement check at `/entitlement` that fails open on a mishandled exception
- component sync at `/integrations` with unverified third-party integrity
- live SOC alerts page at `/soc`
- `LAB_MODE=insecure` for intentionally weak local lab behavior
- `LAB_MODE=secure` for generic failures and simple login lockout
- consistent JSONL telemetry written to `logs/application.jsonl`
- localhost-only Docker Compose port binding

## Login Telemetry Schema

Each login-related JSONL event includes:

| Field | Description |
| --- | --- |
| `timestamp` | UTC ISO-8601 event timestamp |
| `event_type` | `login_success`, `login_failure`, or `account_lockout` |
| `source_ip` | Local/private client address |
| `username` | Fictional local lab username |
| `user_agent` | Client user-agent string, when provided |
| `request_path` | HTTP path that produced the event |
| `http_method` | HTTP method such as `POST` |
| `status_code` | HTTP response status code |
| `lab_mode` | `insecure` or `secure` |
| `reason` | Short machine-readable reason |
| `session_id` | Fake/local session identifier when available, otherwise `null` |

## Search Telemetry Schema

SQLi-like search events use `event_type=suspicious_input` and include:

| Field | Description |
| --- | --- |
| `signal` | `sql_injection_like_pattern` for the current SQLi-style lab |
| `input_name` | Submitted input field, currently `q` |
| `input_value` | Fictional local lab input value |
| `reason` | `accepted_suspicious_input` or `rejected_suspicious_input` |

## Comment Telemetry Schema

XSS-like comment events use `event_type=suspicious_input` and include:

| Field | Description |
| --- | --- |
| `signal` | `xss_like_pattern` for the current XSS-style lab |
| `input_name` | Submitted input field, currently `comment` |
| `input_value` | Fictional local lab input value |
| `reason` | `rendered_suspicious_input` or `rejected_suspicious_input` |

## Admin Access Telemetry Schema

Admin-panel access events use `event_type=admin_access` and include:

| Field | Description |
| --- | --- |
| `signal` | `broken_access_control_pattern` when the panel is reached via the exploit, otherwise `null` |
| `granted` | Whether the admin panel was authorized |
| `reason` | `broken_access_control_role_param`, `authorized_admin_session`, or `missing_admin_role` |

## Outbound Request Telemetry Schema

Server-side fetch events use `event_type=outbound_request` and include:

| Field | Description |
| --- | --- |
| `signal` | `ssrf_internal_target_pattern` for the current SSRF-style lab |
| `target_url` | User-supplied URL the server was asked to fetch |
| `target_host` | Host parsed from `target_url` |
| `reason` | `fetched_internal_target` or `blocked_internal_target` |

## Config Exposure Telemetry Schema

Debug-endpoint access events use `event_type=config_exposure` and include:

| Field | Description |
| --- | --- |
| `signal` | `config_exposure_pattern` when config is disclosed, otherwise `null` |
| `exposed_keys` | List of configuration keys that were disclosed |
| `reason` | `exposed_debug_config` or `debug_endpoint_disabled` |

## Credential Storage Telemetry Schema

Registration events use `event_type=credential_storage` and include:

| Field | Description |
| --- | --- |
| `signal` | `weak_password_hash_pattern` when stored with a weak algorithm, otherwise `null` |
| `algorithm` | Hashing algorithm used, `md5` (insecure) or `pbkdf2_sha256` (secure) |
| `salted` | Whether a per-user salt was applied |
| `reason` | `weak_password_hash` or `strong_password_hash` |

## Sensitive Action Telemetry Schema

Sensitive admin actions use `event_type=sensitive_action` and include:

| Field | Description |
| --- | --- |
| `signal` | `logging_failure_pattern` when the action was unaudited, otherwise `null` |
| `action` | The sensitive operation, currently `role_change` |
| `username` | Authenticated admin actor that performed the action |
| `target_user` | The account the action affected |
| `new_role` | The role applied |
| `audit_logged` / `alerted` | Whether an audit record and alert were produced |
| `reason` | `audit_logging_disabled` or `audit_logged` |

## Profile Import Telemetry Schema

Serialized profile imports use `event_type=profile_import` and include:

| Field | Description |
| --- | --- |
| `signal` | `unsafe_deserialization_pattern` when privileged imported fields were trusted, otherwise `null` |
| `imported_keys` | Keys supplied in the serialized JSON profile |
| `trusted_keys` | Keys accepted into the trusted profile object |
| `privileged_keys` | Client-controlled keys that should not be trusted, such as `role` |
| `reason` | `trusted_serialized_privileged_fields`, `rejected_privileged_serialized_fields`, `validated_profile_import`, or `invalid_profile_payload` |

## Business Action Telemetry Schema

Checkout events use `event_type=business_action` and include:

| Field | Description |
| --- | --- |
| `signal` | `business_logic_abuse_pattern` when the submitted total is below the server-calculated minimum, otherwise `null` |
| `action` | The business operation, currently `checkout` |
| `quantity` | Submitted order quantity |
| `unit_price` / `expected_total` | Server-side item price and expected total |
| `client_total` | Client-submitted final total |
| `allowed_minimum` | Lowest total allowed by server-side discount rules |
| `reason` | `trusted_client_controlled_total`, `rejected_client_controlled_total`, `server_validated_checkout`, or `invalid_checkout_input` |

## Live SOC Alerts

The `/soc` route reads the local JSONL log directly when no generated
`findings.html` report exists. It surfaces recent lab alerts such as:

- unknown username login attempts
- failed login attempts
- account lockouts
- SQLi-like suspicious input
- XSS-like suspicious input
- privilege escalation to the admin panel (broken access control)
- server-side requests to internal targets (SSRF)
- sensitive configuration exposed by the debug endpoint (misconfiguration)
- passwords stored with weak hashing at registration (cryptographic failure)
- sensitive admin actions performed without an audit trail (logging failure)
- privileged fields trusted from serialized profile imports (software/data integrity failure)
- client-controlled checkout totals below the server-calculated minimum (insecure design)

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

The lab console mode switch is protected with a session-bound form token so
other local browser contexts cannot flip `LAB_MODE` with a bare cross-site POST.

The current vulnerable scenarios are a brute-forceable login flow, a SQLi-style
suspicious search input flow, an XSS-style suspicious comment rendering flow, a
broken access control flow on the `/dashboard` admin panel, an SSRF-style
server-side fetch flow on `/fetch`, a security misconfiguration flow on the
`/debug` endpoint, a cryptographic failure flow on the `/register` endpoint, and
a logging & alerting failure flow on the authenticated `/admin/role` action, all
in insecure mode, and an unsafe serialized profile import flow on
`/profile/import`.
The checkout flow on `/checkout` demonstrates client-controlled price abuse, the
entitlement flow on `/entitlement` demonstrates a fail-open mishandled exception
that leaks a stack trace, and the component sync flow on `/integrations`
demonstrates installing a third-party component without verifying its integrity,
all in insecure mode. Future scenarios should keep vulnerable and secure
behavior clearly separated.
