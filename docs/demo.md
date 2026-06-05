<!-- Intro: Walkthrough for generating local login activity and detecting brute-force behavior. -->

# Brute-Force Login Demo

This demo shows how the local lab produces login telemetry and how the
`AUTH-BRUTE-FORCE-001` rule detects repeated failed login attempts.

## Safety Boundary

This scenario is local-only and educational. The demo script only targets
`localhost` or `127.0.0.1` and must not be changed to send requests to
third-party systems.

## Scenario

The demo simulates a local learner submitting repeated failed login attempts
for the fictional `test-user` account. The failed attempts are sent to the
local Flask app at `/login`.

The script can also send one successful login attempt after the failures so
reviewers can see both `login_failure` and `login_success` telemetry.

## Logs Generated

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

## Why The Rule Triggers

`AUTH-BRUTE-FORCE-001` triggers when the detection engine sees five or more
`login_failure` events for the same `source_ip` and `username` within five
minutes.

The demo intentionally creates exactly that local signal.

## Expected Finding

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

## Commands

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

