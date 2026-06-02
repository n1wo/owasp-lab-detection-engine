# Detection Engine

This folder contains the Python detection engine for local lab logs.

The engine reads structured JSONL logs from the local vulnerable application,
parses events, applies documented detection rules, and emits local findings for
learning and testing.

Current responsibilities:

- load JSONL application logs
- normalize log events
- evaluate brute-force login detection logic for local lab scenarios
- report findings in a clear local output format
- report malformed JSONL lines safely without stopping valid parsing

Future responsibilities:

- add rules for SQL injection-like, XSS-like, and broken-access-control lab
  scenarios
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

## Current Rule

`AUTH-BRUTE-FORCE-001` detects repeated `login_failure` events grouped by
`source_ip` and `username`.

It alerts when there are 5 or more failures within 5 minutes and emits:

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
