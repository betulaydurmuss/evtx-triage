---
id: G-021
title: Computer account changes and SID history
applies_to:
  events:
  - Security:4741
  - Security:4742
  - Security:4765
  techniques:
  - T1098
  - T1134
  tactics:
  - Persistence
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4742
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4765
- https://attack.mitre.org/techniques/T1098
- https://attack.mitre.org/techniques/T1134
---

New computer accounts, delegation changes and SID history additions are ways to gain rights in Active Directory without joining a privileged group.

Check next:
- 4741 computer accounts created by ordinary users, since any user can usually add a few.
- 4742 changes to delegation (AllowedToDelegateTo) or to service principal names.
- 4765 SID history added outside a planned domain migration.

Often benign when:
- IT staff join machines to the domain as part of normal provisioning.
