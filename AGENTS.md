<!-- Intro: Agent-facing rules for keeping this local security lab safe, scoped, and well tested. -->

# Agent Guidance

This repository is an intentionally vulnerable educational lab. The vulnerable
app emits structured JSONL telemetry; the Python detection engine evaluates that
telemetry and raises findings. Each scenario is insecure on purpose in
`LAB_MODE=insecure` and has a safer comparison in `LAB_MODE=secure`. Everything
runs locally only.

## Core Rules

- Do not "fix" intentionally vulnerable examples unless the user explicitly asks
  for secure-mode implementation or remediation.
- Keep vulnerable and secure behavior clearly separated in code, docs, logs, and
  tests.
- Keep all security examples local, ethical, and scoped to this lab application.
- Do not add instructions for attacking real systems or third-party services.
- Prefer defensive explanations: what is logged, what signal appears, how a rule
  detects it, and how secure mode differs.

## Current State

The lab maps to the **OWASP Top 10:2025**. Implemented scenarios (route → event
type → signal → rule):

| OWASP 2025 | Route | Event type | Signal | Rule | Severity |
| --- | --- | --- | --- | --- | --- |
| A07 Authentication Failures | `/login` | `login_failure` | (5 in 5 min) | `AUTH-BRUTE-FORCE-001` | Medium |
| A05 Injection | `/search` | `suspicious_input` | `sql_injection_like_pattern` | `WEB-SQLI-PATTERN-001` | Medium |
| A05 Injection | `/comment` | `suspicious_input` | `xss_like_pattern` | `WEB-XSS-PATTERN-001` | Medium |
| A01 Broken Access Control | `/dashboard` | `admin_access` | `broken_access_control_pattern` | `BAC-PRIV-ESC-001` | High |
| A01 Broken Access Control (SSRF) | `/fetch` | `outbound_request` | `ssrf_internal_target_pattern` | `WEB-SSRF-INTERNAL-001` | High |
| A02 Security Misconfiguration | `/debug` | `config_exposure` | `config_exposure_pattern` | `CONFIG-EXPOSURE-001` | High |
| A04 Cryptographic Failures | `/register` | `credential_storage` | `weak_password_hash_pattern` | `CRYPTO-WEAK-001` | High |
| A09 Logging & Alerting Failures | `/admin/role` | `sensitive_action` | `logging_failure_pattern` | `LOG-GAP-001` | High |

Note: in OWASP 2025, SSRF rolled into A01, and SQLi/XSS sit under A05. In-app
help popups use 2025 numbering. The full test suite is currently **105 passing**.

Planned next (see the Roadmap in `README.md`): A10 Mishandling of Exceptional
Conditions (`FAIL-OPEN-001`), then A08, A06, and A03.

## Repository Layout

- `vulnerable-app/vulnerable_app/app.py` — Flask app: routes, telemetry helpers,
  SOC alert logic, and inline HTML templates (all scenarios live in this one
  file).
- `detection-engine/detection_engine/` — `rules.py` (one `detect_*` per rule,
  aggregated by `detect_all`), `parser.py`, `models.py`, `report.py`,
  `__main__.py` (CLI), `__init__.py` (public exports).
- `tests/` — one `test_<scenario>.py` per scenario plus parser/engine/report
  tests. Pure pytest, deterministic, local-only.
- `logs/sample-logs.jsonl` — committed fictional telemetry; running the engine
  on it should emit every implemented rule once.
- `docs/` — `architecture.md`, `threat-model.md`, `detection-rules.md`,
  `demo.md`.

## Common Commands

```bash
pytest                                   # full suite (run from repo root)
docker compose up --build                # start the local vulnerable app
cd detection-engine && python -m detection_engine --log-file ../logs/sample-logs.jsonl
```

## Adding A New Scenario

Follow the established pattern exactly so the lab stays consistent. A scenario is
not done until all of these are updated:

1. **`app.py`**: add a `<SCENARIO>_SIGNAL` constant; the route(s) with an
   insecure/secure split; a `_log_<event>_event` helper; a branch in
   `_soc_alert_from_event`; a new `*_TEMPLATE` that includes a help popup
   labeled with the correct **OWASP 2025** category; a scenario card in
   `HOME_TEMPLATE`; and a link in `NAV_SNIPPET`.
2. **`rules.py`**: add `<RULE>_RULE_ID` and `<SCENARIO>_SIGNAL` constants, a
   `detect_<scenario>` function, and wire it into `detect_all`.
3. **`detection_engine/__init__.py`**: import the new `detect_*` and add it to
   `__all__`.
4. **`tests/test_<scenario>.py`**: cover insecure behavior, secure behavior,
   emitted telemetry, and the detection rule (fires on the signal; does not fire
   on the secure-mode event or unrelated events).
5. **`logs/sample-logs.jsonl`**: append one representative event so the engine
   emits the new finding on the sample log.
6. **Docs**: `detection-rules.md` (table row + rule section), `threat-model.md`
   (scenario list item + section), `architecture.md` (event-type list, current
   rules, component blurb), `demo.md` (walkthrough).
7. **READMEs**: root `README.md` (intro count, Features, Detection Rules table,
   "Run The Detection Engine" findings list, Log Schema event types, test count,
   Roadmap → move the category to Covered), plus `detection-engine/README.md`,
   `vulnerable-app/README.md`, and `logs/README.md`.

### Detection-engine conventions

- Each rule matches on `event_type` **and** the scenario `signal`, and emits one
  finding per matching event (brute force is the exception: it correlates
  failures in a time window).
- Secure-mode events must carry **no** signal so they are not flagged.
- `DetectionFinding` fields: `rule_id`, `severity`, `source_ip`, `username`,
  `event_count`, `first_seen`, `last_seen`, `reason`.

## Testing Rules

- Any new feature, behavior change, scenario, secure-mode behavior, logging
  change, or engine change must include matching pytest coverage unless the user
  asks for documentation-only work.
- Keep tests local and deterministic: fictional users, local/private addresses,
  temp files, lab-only paths.
- Test both vulnerable and secure behavior, and the structured log output.
- Run `pytest` before considering a task complete. If pytest cannot run, explain
  why and state what validation was performed instead.

## Documentation Rules

- Update `README.md` when setup, commands, scenario count, or major behavior
  changes (keep the test count accurate).
- Update `docs/detection-rules.md` when detection logic changes.
- Update `docs/threat-model.md` when adding or changing vulnerable scenarios.
- Update `docs/architecture.md` when component boundaries, data flow, event
  types, or deployment shape change.
- Keep `docs/demo.md`, the sub-READMEs, and `logs/sample-logs.jsonl` in sync
  with implemented scenarios.

## Implementation Boundaries

- Keep the vulnerable app suitable for local learning only.
- Use private/local example values such as `127.0.0.1`, `localhost`, test users,
  and fake paths.
- Avoid real exploit targets, real credentials, and real external services.
  Where a scenario would touch the network or persist data (e.g. SSRF, crypto,
  logging), simulate it deterministically rather than performing it for real.
- Mark placeholders clearly when functionality is not implemented yet.

## Demo Script Rules

- Demo scripts must only target `localhost` or `127.0.0.1`.
- Do not modify demo scripts to send traffic to third-party systems, public
  websites, real services, or non-local network ranges.
- Demo scripts should fail safely with clear instructions when the local lab app
  is not running.
- Keep demo payloads fictional, local, and limited to the implemented lab
  scenario.
