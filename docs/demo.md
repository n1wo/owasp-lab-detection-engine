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

## Insecure Design Checkout Scenario

This scenario has no demo script. It is driven manually against the local
`/checkout` route, which simulates a checkout workflow without processing any
real payment or persisting an order.

In insecure mode the route trusts the client-submitted final total. In secure
mode the route recalculates the minimum allowed total from server-side product
data and rejects impossible discounts.

### Logs Generated

The app writes a `business_action` event to:

```text
logs/application.jsonl
```

The checkout event includes:

- `event_type`: `business_action`
- `signal`: `business_logic_abuse_pattern` when the submitted total is below
  the server-calculated minimum
- `request_path`: `/checkout`
- `action`: `checkout`
- `expected_total`, `allowed_minimum`, and `client_total`
- `reason`: `trusted_client_controlled_total`,
  `rejected_client_controlled_total`, or `server_validated_checkout`
- `lab_mode`

### Why The Rule Triggers

`DESIGN-LOGIC-001` triggers when the detection engine sees a `business_action`
event with `signal` set to `business_logic_abuse_pattern`. The rule fires for
both accepted insecure-mode abuse and rejected secure-mode attempts.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `DESIGN-LOGIC-001`
- `severity`: `High`
- `source_ip`
- `username`: `test-user`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then submit a zero-total checkout:

```bash
docker compose up --build
curl -X POST -d "quantity=1&client_total=0.00" "http://127.0.0.1:8080/checkout"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Unsafe Profile Import Scenario

This scenario has no demo script. It is driven manually against the local
`/profile/import` route, which imports a serialized JSON profile object.

In insecure mode the route trusts every field in the imported object, including
privileged fields such as `role` and `feature_flags`. In secure mode the same
payload is rejected unless it contains only allowlisted preference fields.

### Logs Generated

The app writes a `profile_import` event to:

```text
logs/application.jsonl
```

The profile-import event includes:

- `event_type`: `profile_import`
- `signal`: `unsafe_deserialization_pattern` (insecure exploit) or absent
- `request_path`: `/profile/import`
- `imported_keys`, `trusted_keys`, and `privileged_keys`
- `reason`: `trusted_serialized_privileged_fields`,
  `rejected_privileged_serialized_fields`, or `validated_profile_import`
- `lab_mode`

### Why The Rule Triggers

`INTEGRITY-DESERIALIZE-001` triggers when the detection engine sees a
`profile_import` event with `signal` set to
`unsafe_deserialization_pattern`. Rejected secure-mode imports carry no signal
and do not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `INTEGRITY-DESERIALIZE-001`
- `severity`: `High`
- `source_ip`
- `username`: `test-user`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then submit a profile containing privileged fields:

```bash
docker compose up --build
curl -X POST --data-urlencode 'payload={"display_name":"test-user","theme":"dark","timezone":"UTC","role":"admin","feature_flags":["admin_panel"]}' "http://127.0.0.1:8080/profile/import"
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

## Security Misconfiguration Scenario

This scenario has no demo script. It is driven manually against the local
`/debug` route, a diagnostics endpoint left enabled by misconfiguration.

In insecure mode, visiting `/debug` dumps live application configuration,
including the signing secret key and the lab credential set. In secure mode the
endpoint is disabled and returns HTTP `404`.

### Logs Generated

The app writes a `config_exposure` event to:

```text
logs/application.jsonl
```

The misconfiguration event includes:

- `event_type`: `config_exposure`
- `signal`: `config_exposure_pattern`
- `request_path`: `/debug`
- `exposed_keys`: the configuration keys disclosed (e.g. `secret_key`)
- `reason`: `exposed_debug_config` (insecure) or `debug_endpoint_disabled` (secure)
- `lab_mode`

### Why The Rule Triggers

`CONFIG-EXPOSURE-001` triggers when the detection engine sees a
`config_exposure` event with `signal` set to `config_exposure_pattern`. The
disabled-endpoint event in secure mode carries no signal and does not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `CONFIG-EXPOSURE-001`
- `severity`: `High`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then open the exposed debug endpoint:

```bash
docker compose up --build
curl "http://127.0.0.1:8080/debug"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Cryptographic Failures Scenario

This scenario has no demo script. It is driven manually against the local
`/register` route, which demonstrates how a password would be stored.

In insecure mode the password is stored as an unsalted MD5 digest. In secure
mode it is stored as a per-user salted PBKDF2-HMAC-SHA256 hash. No account is
persisted.

### Logs Generated

The app writes a `credential_storage` event to:

```text
logs/application.jsonl
```

The cryptographic-storage event includes:

- `event_type`: `credential_storage`
- `signal`: `weak_password_hash_pattern` (insecure) or absent (secure)
- `request_path`: `/register`
- `algorithm`: `md5` (insecure) or `pbkdf2_sha256` (secure)
- `salted`: `false` (insecure) or `true` (secure)
- `reason`: `weak_password_hash` or `strong_password_hash`
- `lab_mode`

### Why The Rule Triggers

`CRYPTO-WEAK-001` triggers when the detection engine sees a `credential_storage`
event with `signal` set to `weak_password_hash_pattern`. Secure-mode storage
carries no signal and does not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `CRYPTO-WEAK-001`
- `severity`: `High`
- `source_ip`
- `username`: the registered lab username
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then register a local lab account:

```bash
docker compose up --build
curl -X POST -d "username=lab-user&password=hunter2" "http://127.0.0.1:8080/register"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Security Logging & Alerting Failures Scenario

This scenario can be driven by the included demo script or manually as the
fictional local admin account against the `/admin/role` route, a sensitive
privilege change that should always be audited.

In insecure mode the role change is performed with no audit or alert record. In
secure mode the same action writes a full audit record and is marked alerted. No
role is persisted.

### Logs Generated

The app writes a `sensitive_action` event to:

```text
logs/application.jsonl
```

The sensitive-action event includes:

- `event_type`: `sensitive_action`
- `signal`: `logging_failure_pattern` (insecure) or absent (secure)
- `request_path`: `/admin/role`
- `action`: `role_change`
- `username`: the authenticated admin actor
- `target_user` and `new_role`
- `audit_logged` / `alerted`: `false` (insecure) or `true` (secure)
- `reason`: `audit_logging_disabled` or `audit_logged`
- `lab_mode`

### Why The Rule Triggers

`LOG-GAP-001` triggers when the detection engine sees a `sensitive_action` event
with `signal` set to `logging_failure_pattern`. The external detection engine
catches the gap that the app's own monitoring missed. Audited actions carry no
signal and do not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `LOG-GAP-001`
- `severity`: `High`
- `source_ip`
- `username`: `admin` (the acting administrator)
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, sign in as the fictional admin, then perform an unaudited
role change:

```bash
docker compose up --build
python scripts/generate_logging_demo.py
```

Or trigger it directly with curl:

```bash
curl -c /tmp/owasp-lab-cookies -X POST \
  -d "username=admin&password=admin-password" \
  "http://127.0.0.1:8080/login"
curl -b /tmp/owasp-lab-cookies -X POST \
  -d "user=test-user&role=admin" \
  "http://127.0.0.1:8080/admin/role"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Mishandling of Exceptional Conditions Scenario

This scenario has no demo script. It is driven manually against the local
`/entitlement` route, which verifies a premium-entitlement token.

A malformed or tampered token makes the check raise. In insecure mode the error
is swallowed, the check fails open (premium access granted), and the stack trace
is leaked to the client. In secure mode the same error fails closed: access is
denied with a generic message and no internal detail leaks.

### Logs Generated

The app writes an `exception_handling` event to:

```text
logs/application.jsonl
```

The exception-handling event includes:

- `event_type`: `exception_handling`
- `signal`: `fail_open_pattern` (insecure fail-open) or absent
- `request_path`: `/entitlement`
- `error_type`, `fail_open`, `stack_trace_leaked`, and `granted`
- `reason`: `fail_open_on_exception`, `fail_closed_on_exception`, or
  `entitlement_verified`
- `lab_mode`

### Why The Rule Triggers

`FAIL-OPEN-001` triggers when the detection engine sees an `exception_handling`
event with `signal` set to `fail_open_pattern`. Fail-closed secure-mode handling
carries no signal and does not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `FAIL-OPEN-001`
- `severity`: `High`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then submit a tampered entitlement token:

```bash
docker compose up --build
curl -X POST --data-urlencode 'token=premium.eyJwbGFuIjoicHJlbWl1bSJ9.t4mp3r-ed' "http://127.0.0.1:8080/entitlement"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

## Software Supply Chain Failures Scenario

This scenario has no demo script. It is driven manually against the local
`/integrations` route, which syncs third-party components declared in a JSON
manifest.

In insecure mode the route installs every declared component without verifying
its integrity hash against the pinned baseline, so a tampered or swapped
artifact is trusted. In secure mode each component is verified and any
tampered or unknown component is rejected.

### Logs Generated

The app writes a `dependency_load` event to:

```text
logs/application.jsonl
```

The dependency-load event includes:

- `event_type`: `dependency_load`
- `signal`: `supply_chain_compromise_pattern` (insecure unverified install) or
  absent
- `request_path`: `/integrations`
- `components` and `compromised_components`
- `reason`: `unverified_component_integrity`, `rejected_untrusted_component`, or
  `verified_component_integrity`
- `lab_mode`

### Why The Rule Triggers

`SUPPLY-CHAIN-001` triggers when the detection engine sees a `dependency_load`
event with `signal` set to `supply_chain_compromise_pattern`. Verified and
rejected syncs carry no signal and do not match.

### Expected Finding

The detection engine should emit a finding containing:

- `rule_id`: `SUPPLY-CHAIN-001`
- `severity`: `High`
- `source_ip`
- `username`: `anonymous`
- `event_count`: `1`
- `first_seen`
- `last_seen`
- `reason`

### Commands

Start the local app, then sync a manifest with a tampered integrity hash:

```bash
docker compose up --build
curl -X POST --data-urlencode 'manifest=[{"name":"payment-widget","version":"2.0.1","integrity":"sha256-deadbeef"}]' "http://127.0.0.1:8080/integrations"
```

Run the detection engine:

```bash
cd detection-engine
python -m detection_engine --log-file ../logs/application.jsonl
python -m detection_engine --log-file ../logs/application.jsonl --json
```

