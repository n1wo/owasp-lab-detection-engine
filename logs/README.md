<!-- Intro: Guidance for safe fictional JSONL log files used by the lab. -->

# Logs

This folder stores sample and future generated JSONL logs from the local lab
application.

Log entries should use fictional local-only values such as `127.0.0.1`,
`localhost`, test usernames, and fake paths. Do not include real credentials,
production data, or logs from third-party systems.

Current files:

- `sample-logs.jsonl` - safe fictional examples for parser and detection rule
  development, including implemented brute-force, SQLi-style, XSS-style,
  broken-access-control, SSRF, and security-misconfiguration signals
- `application.jsonl` - generated locally by the vulnerable app when it runs
