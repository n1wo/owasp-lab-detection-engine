<!-- Intro: Local detection-engine overview, usage notes, and rule responsibilities. -->

# Detection Engine

This folder contains the Python detection engine for local lab logs.

The engine reads structured JSONL logs from the local vulnerable application,
parses events, applies documented detection rules, and emits local findings for
learning and testing.

Current responsibilities:

- load JSONL application logs
- normalize log events
- evaluate brute-force login detection logic for local lab scenarios
- evaluate SQLi-like suspicious-input detection logic for local lab scenarios
- evaluate XSS-like suspicious-input detection logic for local lab scenarios
- evaluate broken-access-control detection logic for local lab scenarios
- evaluate SSRF (internal-target) detection logic for local lab scenarios
- report findings in a clear local output format
- report malformed JSONL lines safely without stopping valid parsing
- ignore unknown additional log fields safely while preserving the raw event

Future responsibilities:

- optionally export a Wazuh/SIEM-friendly format later

## Usage

From this folder:

```bash
python -m detection_engine --log-file ../logs/application.jsonl
```

JSON output:

```bash
python -m detection_engine --log-file ../logs/application.jsonl --json
```

HTML dashboard report (self-contained, opens offline in any browser):

```bash
python -m detection_engine --log-file ../logs/application.jsonl --html ../logs/findings.html
```

## Current Rules

`AUTH-BRUTE-FORCE-001` detects repeated `login_failure` events grouped by
`source_ip` and `username`.

It alerts when there are 5 or more failures within 5 minutes.

`WEB-SQLI-PATTERN-001` detects `suspicious_input` events where `signal` is
`sql_injection_like_pattern`.

`WEB-XSS-PATTERN-001` detects `suspicious_input` events where `signal` is
`xss_like_pattern`.

`BAC-PRIV-ESC-001` detects `admin_access` events where `signal` is
`broken_access_control_pattern` (admin panel authorized via a client-supplied
role parameter rather than a real admin session). Severity is High.

`WEB-SSRF-INTERNAL-001` detects `outbound_request` events where `signal` is
`ssrf_internal_target_pattern` (a server-side fetch aimed at a loopback,
private, link-local, or otherwise internal target). Severity is High.

All rules emit:

- `rule_id`
- `severity`
- `source_ip`
- `username`
- `event_count`
- `first_seen`
- `last_seen`
- `reason`

## Local Boundary

This engine is for the repository's local lab logs only. It is not intended for
monitoring third-party systems or real production logs.
