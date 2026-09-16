---
id: G-013
title: Logons with explicitly supplied credentials
applies_to:
  events:
  - Security:4648
  techniques:
  - T1078
  tactics:
  - Lateral Movement
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648
- https://attack.mitre.org/techniques/T1078
---

A process supplied another account's credentials instead of using its own token. That is normal for runas and scheduled tasks, and it is also the footprint of lateral movement tools connecting with stolen credentials.

Check next:
- The calling account (Subject) against the credentials used (Target): an ordinary user supplying an administrator's credentials.
- TargetServerName: connections to many hosts in a short time.
- ProcessName: tools running from user or temporary folders.

Often benign when:
- A scheduled task or service uses a stored service account and targets the same server every time.
