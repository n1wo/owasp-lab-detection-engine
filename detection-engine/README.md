# Detection Engine

This folder will contain the future Python detection engine.

The planned engine will read structured JSONL logs from the local vulnerable
application, parse events, apply documented detection rules, and emit local
findings for learning and testing.

Planned responsibilities:

- load JSONL application logs
- normalize log events
- evaluate rule logic for local lab scenarios
- report findings in a clear local output format
- optionally export a Wazuh/SIEM-friendly format later

No detection engine code is implemented yet.

