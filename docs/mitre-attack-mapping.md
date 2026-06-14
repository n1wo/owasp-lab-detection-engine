<!-- Intro: MITRE ATT&CK references for the local lab detection rules. -->

# MITRE ATT&CK Mapping

This project is a local educational lab, not a production SIEM. The mappings
below connect each internal rule to a close MITRE ATT&CK technique so learners
can explain what kind of attacker behavior the rule represents.

| Internal Rule ID | Rule Name | MITRE Technique | Why It Fits | Official Link |
| --- | --- | --- | --- | --- |
| `AUTH-BRUTE-FORCE-001` | Login brute force | T1110 - Brute Force | Repeated failed login attempts model password guessing against a valid account. | https://attack.mitre.org/techniques/T1110/ |
| `WEB-SQLI-PATTERN-001` | SQL injection-like input | T1190 - Exploit Public-Facing Application | SQLi-style input models exploitation attempts against a web application route. | https://attack.mitre.org/techniques/T1190/ |
| `WEB-XSS-PATTERN-001` | XSS-like input | T1190 - Exploit Public-Facing Application | XSS-style input is a web application exploit attempt against user-controlled input handling. | https://attack.mitre.org/techniques/T1190/ |
| `BAC-PRIV-ESC-001` | Broken access control privilege escalation | T1190 - Exploit Public-Facing Application | The attacker abuses a public web route to reach an admin-only function. | https://attack.mitre.org/techniques/T1190/ |
| `WEB-SSRF-INTERNAL-001` | SSRF internal target access | T1190 - Exploit Public-Facing Application | SSRF abuses a public-facing web route to make the server reach internal resources. | https://attack.mitre.org/techniques/T1190/ |
| `CONFIG-EXPOSURE-001` | Exposed debug configuration | T1552.001 - Credentials In Files | The exposed debug page discloses secrets and credentials stored in application configuration. | https://attack.mitre.org/techniques/T1552/001/ |
| `CRYPTO-WEAK-001` | Weak password hashing | T1552.001 - Credentials In Files | Weakly stored password material can become recoverable credential data after exposure. | https://attack.mitre.org/techniques/T1552/001/ |
| `LOG-GAP-001` | Sensitive action without audit trail | T1562 - Impair Defenses | Missing audit and alert records reduce defensive visibility around privileged actions. | https://attack.mitre.org/techniques/T1562/ |
| `INTEGRITY-DESERIALIZE-001` | Unsafe serialized profile import | T1190 - Exploit Public-Facing Application | A public web route trusts client-controlled serialized data and grants privileged state. | https://attack.mitre.org/techniques/T1190/ |
| `DESIGN-LOGIC-001` | Client-controlled checkout total | T1565 - Data Manipulation | The attacker manipulates business data in a valid-looking workflow request. | https://attack.mitre.org/techniques/T1565/ |
| `FAIL-OPEN-001` | Fail-open on mishandled exception | T1211 - Exploitation for Defense Evasion | A mishandled error makes the access check fail open, bypassing the security decision it should have enforced. | https://attack.mitre.org/techniques/T1211/ |
| `SUPPLY-CHAIN-001` | Unverified third-party component | T1195 - Supply Chain Compromise | Installing a component without verifying its integrity against a pinned baseline trusts a tampered or swapped build artifact. | https://attack.mitre.org/techniques/T1195/ |
