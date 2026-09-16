---
id: G-005
title: Repeated authentication failures (password guessing or spraying)
applies_to:
  events:
  - Security:4625
  - Security:4776
  techniques:
  - T1110
  - T1110.001
  - T1110.003
  tactics:
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
- https://attack.mitre.org/techniques/T1110
- https://attack.mitre.org/techniques/T1110/001
- https://attack.mitre.org/techniques/T1110/003
---

Logon or credential validation attempts failed. The pattern across events matters more than any single failure.

Check next:
- Many failures for one account from one source: password guessing.
- One or two failures each for many accounts from one source: password spraying.
- Status and SubStatus, which separate wrong passwords from unknown, disabled or locked accounts.
- A successful logon (4624) for the same account or source right after the failures.

Often benign when:
- A user with an expired password, or a service with a stale stored credential, fails repeatedly from its usual host.
