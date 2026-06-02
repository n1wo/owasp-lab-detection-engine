# Detection Rules

This document tracks planned detection rules for the local lab. Rules are
drafts until the vulnerable app, structured logs, and detection engine are
implemented.

| Rule ID | Goal | Example signal | Severity | Status |
| --- | --- | --- | --- | --- |
| AUTH-BRUTE-FORCE-001 | Detect repeated failed login attempts against the local lab login flow | Multiple `login_failure` events for the same username or source IP in a short time window | Medium | Planned |
| WEB-SQLI-PATTERN-001 | Detect SQL injection-like input patterns submitted to local lab routes | `suspicious_input` event with `signal` set to `sql_injection_like_pattern` | Medium | Planned |
| WEB-XSS-PATTERN-001 | Detect XSS-like input patterns submitted to local lab routes | `suspicious_input` event with `signal` set to `xss_like_pattern` | Medium | Planned |
| WEB-BROKEN-ACCESS-001 | Detect possible broken access control behavior in local lab routes | `access_denied` or unexpected access events for fake restricted paths | High | Planned |

## Rule Documentation Expectations

When rule logic is implemented, each rule should document:

- expected input log fields
- local lab scenario covered
- vulnerable-mode behavior
- secure-mode behavior
- detection threshold or matching logic
- false-positive considerations inside the lab

