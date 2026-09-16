---
id: G-020
title: New accounts and privileged group membership
applies_to:
  events:
  - Security:4720
  - Security:4732
  - Security:4781
  techniques:
  - T1136
  - T1136.001
  - T1098
  tactics:
  - Persistence
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4781
- https://attack.mitre.org/techniques/T1136
- https://attack.mitre.org/techniques/T1136/001
- https://attack.mitre.org/techniques/T1098
---

Creating an account, or adding one to a privileged group, gives an attacker access that no longer depends on the credentials they stole first.

Check next:
- 4732 additions to Administrators or Remote Desktop Users, and which account made them.
- 4720 accounts created outside the normal provisioning process; 4781 renames that make an account look like a service account.
- Whether the new account signs in soon afterwards, and from where.

Often benign when:
- Help desk or provisioning tooling creates accounts during working hours through a known administrative account.
