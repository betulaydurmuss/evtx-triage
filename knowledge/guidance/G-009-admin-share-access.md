---
id: G-009
title: Administrative share access
applies_to:
  events:
  - Security:5140
  - Security:5145
  techniques:
  - T1021
  - T1021.002
  tactics:
  - Lateral Movement
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
- https://attack.mitre.org/techniques/T1021
- https://attack.mitre.org/techniques/T1021/002
---

A client connected to a share on this host. Access to ADMIN$, C$ or IPC$ from another machine is the usual first step of remote execution over SMB.

Check next:
- ShareName, and for 5145 the RelativeTargetName: executables or scripts copied into ADMIN$ or C$\Windows.
- The source IpAddress and account, and whether that host normally administers this one.
- A service installation, scheduled task or new process shortly after the access.

Often benign when:
- Management, deployment and backup servers routinely read administrative shares.
