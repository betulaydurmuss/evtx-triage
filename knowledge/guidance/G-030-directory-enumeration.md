---
id: G-030
title: Active Directory account and group enumeration
applies_to:
  events:
  - Security:4661
  - Security:4662
  techniques:
  - T1087
  - T1087.002
  - T1069
  - T1069.002
  - T1201
  tactics:
  - Discovery
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4661
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662
- https://attack.mitre.org/techniques/T1087
- https://attack.mitre.org/techniques/T1087/002
- https://attack.mitre.org/techniques/T1069
- https://attack.mitre.org/techniques/T1069/002
- https://attack.mitre.org/techniques/T1201
---

Before moving laterally, attackers list domain administrators, privileged groups and the password policy. Directory and SAM access records show these queries.

Check next:
- 4661 handle requests on SAM objects such as the domain, Domain Admins or many user objects, from an account that is not a management server.
- A burst of queries within seconds, which suggests a tool rather than a person.
- The session source: a network logon and IPC$ share access just before.
- Password policy enumeration followed by authentication failures across many accounts.

Often benign when:
- Identity management, auditing or monitoring software enumerates groups on a schedule.
