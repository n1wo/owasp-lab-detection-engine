<!-- Intro: Agent-facing rules for keeping this local security lab safe, scoped, and well tested. -->

# Agent Guidance

This repository contains an intentionally vulnerable educational lab. Some
future code will be insecure on purpose so learners can observe, log, and detect
specific local-only scenarios.

## Core Rules

- Do not automatically fix intentionally vulnerable examples unless the user
  explicitly asks for secure-mode implementation or remediation.
- Keep vulnerable examples and secure examples clearly separated in code,
  documentation, logs, and tests.
- Keep all security examples local, ethical, and scoped to this lab application.
- Do not add instructions for attacking real systems or third-party services.
- Prefer defensive explanations: what is logged, what signal appears, how a
  rule detects it, and how secure mode should differ.

## Common Commands

These commands are implemented and working:

```bash
docker compose up --build
pytest
cd detection-engine && python -m detection_engine --log-file ../logs/application.jsonl
```

## Testing Rules

- Build out the pytest test kit as features are implemented.
- Any new feature, behavior change, vulnerability scenario, secure-mode
  behavior, logging change, or detection-engine change should include matching
  pytest coverage unless the user explicitly asks for documentation-only work.
- Keep tests local and deterministic. Use fictional users, local/private
  addresses, temporary files, and lab-only paths.
- Test both vulnerable and secure behavior when a feature has both modes.
- Test structured log output whenever application behavior is expected to emit
  logs.
- Run `pytest` before considering an implementation task complete. If pytest
  cannot be run, explain why and state what validation was performed instead.

## Documentation Rules

- Update `README.md` when setup, commands, or major project behavior changes.
- Update `docs/detection-rules.md` when detection logic changes.
- Update `docs/threat-model.md` when adding new vulnerabilities or changing
  vulnerable scenarios.
- Update `docs/architecture.md` when component boundaries, data flow, or
  deployment shape changes.

## Implementation Boundaries

- Keep the vulnerable app suitable for local learning only.
- Use private/local example values such as `127.0.0.1`, `localhost`, test users,
  and fake paths.
- Avoid real exploit targets, real credentials, and real external services.
- Mark placeholders clearly when functionality is not implemented yet.

## Demo Script Rules

- Demo scripts must only target `localhost` or `127.0.0.1`.
- Do not modify demo scripts to send traffic to third-party systems, public
  websites, real services, or non-local network ranges.
- Demo scripts should fail safely with clear instructions when the local lab app
  is not running.
- Keep demo payloads fictional, local, and limited to the implemented lab
  scenario.
