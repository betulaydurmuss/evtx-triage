---
id: G-007
title: Directory replication rights and DCSync
applies_to:
  events:
  - Security:4662
  - Security:5136
  techniques:
  - T1003
  - T1003.006
  - T1098
  tactics:
  - Credential Access
  - Persistence
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136
- https://attack.mitre.org/techniques/T1003
- https://attack.mitre.org/techniques/T1003/006
- https://attack.mitre.org/techniques/T1098
---

An account with directory replication rights can ask a domain controller for the password data of any account, without running code on the domain controller.

Check next:
- 4662 events whose properties include DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) or DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2), requested by an account that is not a domain controller.
- 5136 changes to the domain object's security descriptor that grant those rights to an ordinary account.
- Who made the change, from which session, and whether the log was cleared afterwards.

Often benign when:
- The requester is a domain controller computer account or a documented directory synchronisation service.
