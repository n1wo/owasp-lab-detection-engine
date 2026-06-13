<!-- Intro: Walkthroughs for generating local lab activity and detecting implemented rules. -->

# Demo Walkthroughs

These demos show how the local lab produces telemetry and how implemented
detection rules identify suspicious local-only behavior.

## Safety Boundary

This scenario is local-only and educational. The demo script only targets
`localhost` or `127.0.0.1` and must not be changed to send requests to
third-party systems.

## Brute-Force Login Scenario

The demo simulates a local learner submitting repeated failed login attempts
for the fictional `test-user` account. The failed attempts are sent to the
local Flask app at `/login`.

The script can also send one successful login attempt after the failures so
reviewers can see both `login_failure` and `login_success` telemetry.

### Logs Generated

The vulnerable app writes JSONL events to:

```text
logs/application.jsonl
```

The brute-force part of the demo generates at least five `login_failure` events
with the same:

- `source_ip`
- `username`
- `request_path`
- `lab_mode`

Each event follows the current login telemetry schema documented in
`README.md` and `docs/architecture.md`.

### Why The Rule Triggers

`AUTH-BRUTE-FORCE-001` triggers when the detection engine sees five or more
`login_failure` events for the same `source_ip` and `username` within five
minutes.

The demo intentionally creates exactly that local signal.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `AUTH-BRUTE-FORCE-001`
- `severity`: `Medium`
- `source_ip`: usually `127.0.0.1`
- `username`: `test-user`
- `event_count`: at least `5`
- `first_seen`
- `last_seen`
- `reason`

The finding means the local lab observed repeated failed login attempts that
match the educational brute-force detection threshold. It does not indicate
activity against a real external system.

### Commands

Start the local app:

```bash
docker compose up --build
```

In another terminal, generate local demo login activity:

```bash
python scripts/generate_login_demo.py
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## SQLi-Style Search Scenario

The SQLi-style demo sends one local search request to `/search` with a
fictional SQLi-like input string. The app records the request as
`suspicious_input` telemetry.

In insecure mode, the route accepts the input and returns local demo results.
In secure mode, the route rejects the same input with HTTP `400`. Both modes
log the suspicious input so the detector can emit a finding.

### Logs Generated

The app writes a `suspicious_input` event to:

```text
logs/application.jsonl
```

The SQLi-style event includes:

- `event_type`: `suspicious_input`
- `signal`: `sql_injection_like_pattern`
- `request_path`: `/search`
- `input_name`: `q`
- `lab_mode`
- `reason`

### Why The Rule Triggers

`WEB-SQLI-PATTERN-001` triggers when the detection engine sees a
`suspicious_input` event with `signal` set to
`sql_injection_like_pattern`.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `WEB-SQLI-PATTERN-001`
- `severity`: `Medium`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app:

```bash
docker compose up --build
```

In another terminal, generate local SQLi-like search activity:

```bash
python scripts/generate_sqli_demo.py
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## XSS-Style Comment Scenario

The XSS-style demo sends one local comment submission to `/comment` with a
fictional XSS-like input string. The app records the request as
`suspicious_input` telemetry.

In insecure mode, the route renders the submitted value as HTML in the local
preview. In secure mode, the route rejects the same input with HTTP `400`.
Both modes log the suspicious input so the detector can emit a finding.

### Logs Generated

The app writes a `suspicious_input` event to:

```text
logs/application.jsonl
```

The XSS-style event includes:

- `event_type`: `suspicious_input`
- `signal`: `xss_like_pattern`
- `request_path`: `/comment`
- `input_name`: `comment`
- `lab_mode`
- `reason`

### Why The Rule Triggers

`WEB-XSS-PATTERN-001` triggers when the detection engine sees a
`suspicious_input` event with `signal` set to `xss_like_pattern`.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `WEB-XSS-PATTERN-001`
- `severity`: `Medium`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app:

```bash
docker compose up --build
```

In another terminal, generate local XSS-like comment activity:

```bash
python scripts/generate_xss_demo.py
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Broken Access Control Scenario

This scenario has no demo script. It is driven manually against the local
`/dashboard` admin panel so reviewers can see the broken access control check.

In insecure mode, requesting the dashboard with a client-supplied `role=admin`
parameter grants the admin panel without authenticating as the admin account.
In secure mode, the same request is denied with HTTP `403`.

### Logs Generated

The app writes an `admin_access` event to:

```text
logs/application.jsonl
```

The broken-access-control event includes:

- `event_type`: `admin_access`
- `signal`: `broken_access_control_pattern`
- `request_path`: `/dashboard`
- `reason`: `broken_access_control_role_param`
- `lab_mode`

### Why The Rule Triggers

`BAC-PRIV-ESC-001` triggers when the detection engine sees an `admin_access`
event with `signal` set to `broken_access_control_pattern`. Legitimate admin
sessions log `admin_access` without the signal and do not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `BAC-PRIV-ESC-001`
- `severity`: `High`
- `source_ip`
- `username`: often `guest`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then trigger the local exploit attempt:

```bash
docker compose up --build
curl "http://127.0.0.1:8080/dashboard?role=admin"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## SSRF Scenario

This scenario has no demo script. It is driven manually against the local
`/fetch` route. The lab never performs real network I/O; it simulates the
response so the scenario stays deterministic and safe.

In insecure mode, the route "fetches" any user-supplied URL, including internal
and link-local targets such as the cloud metadata endpoint. In secure mode, the
route enforces an http(s) allowlist and refuses internal targets with HTTP
`400`. Both modes log the attempt so the detector can emit a finding.

### Logs Generated

The app writes an `outbound_request` event to:

```text
logs/application.jsonl
```

The SSRF event includes:

- `event_type`: `outbound_request`
- `signal`: `ssrf_internal_target_pattern`
- `request_path`: `/fetch`
- `target_url` and `target_host`
- `reason`: `fetched_internal_target` (insecure) or `blocked_internal_target` (secure)
- `lab_mode`

### Why The Rule Triggers

`WEB-SSRF-INTERNAL-001` triggers when the detection engine sees an
`outbound_request` event with `signal` set to `ssrf_internal_target_pattern`.
The rule fires whether the attempt was served (insecure) or blocked (secure).

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `WEB-SSRF-INTERNAL-001`
- `severity`: `High`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then trigger a local internal-target fetch:

```bash
docker compose up --build
curl "http://127.0.0.1:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

