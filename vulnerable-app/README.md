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
- JSONL login events written to `logs/application.jsonl`
- localhost-only Docker Compose port binding

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
