<!-- Intro: Contribution workflow and safety rules for this local security lab. -->

# Contributing

Thanks for helping improve OWASP Lab Detection Engine. This repository contains
intentional vulnerable examples, so contributions must keep the lab safe,
local, and clearly documented.

## Safety Boundary

This project is for local defensive learning only.

Do not contribute:

- instructions for attacking third-party systems
- payloads or scripts that target public hosts or non-local networks
- real credentials, real user data, or production logs
- changes that make the vulnerable app suitable for public deployment

Demo scripts must only target `localhost` or `127.0.0.1`.

## Good First Contributions

Useful contributions include:

- tests for existing rules and demo scripts
- clearer documentation or walkthroughs
- local-only detection scenarios with secure and insecure behavior
- parser and reporting improvements
- accessibility or usability improvements for local lab pages

## Development Setup

Create and activate a virtual environment, then install dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run the test suite:

```bash
python -m pytest
```

On Windows/OneDrive, use a repo-local temp folder if pytest prints cache or
temporary-directory warnings:

```powershell
python -m pytest --basetemp .pytest_cache\tmp
```

## Contribution Checklist

Before opening a pull request:

- keep the change focused on one scenario, bug, or documentation improvement
- add or update pytest coverage for behavior changes
- update `README.md` when commands, setup, or major behavior changes
- update `docs/detection-rules.md` when detection logic changes
- update `docs/threat-model.md` when scenarios or safety assumptions change
- update `docs/architecture.md` when component boundaries or data flow changes
- run the full test suite

## Adding A New Scenario

New vulnerable scenarios should include:

- insecure-mode behavior for the local lab
- secure-mode comparison behavior
- structured JSONL telemetry
- detection logic when applicable
- deterministic tests
- a localhost-only demo script when useful
- documentation for rules, threat model, and demo flow

Keep vulnerable and secure examples clearly separated in code, tests, and docs.

## Reporting Accidental Security Issues

If you find an accidental security issue that is not part of an intentional lab
scenario, follow `SECURITY.md` and report it privately to the maintainer.
