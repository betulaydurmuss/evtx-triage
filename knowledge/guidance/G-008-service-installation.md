---
id: G-008
title: Service installed on a host (remote execution or persistence)
applies_to:
  events:
  - System:7045
  techniques:
  - T1569
  - T1569.002
  - T1543
  - T1543.003
  tactics:
  - Execution
  - Persistence
sources:
- https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview
- https://attack.mitre.org/techniques/T1569
- https://attack.mitre.org/techniques/T1569/002
- https://attack.mitre.org/techniques/T1543
- https://attack.mitre.org/techniques/T1543/003
---

A new service was registered. Remote execution tools create a short-lived service to run one command; persistence installs a long-lived one.

Check next:
- ImagePath: commands through cmd.exe or powershell, encoded arguments, binaries in temporary or share paths, random-looking service names.
- AccountName: a service running as LocalSystem has full control of the host.
- A network logon and ADMIN$ share access from another host just before, which points to remote execution.
- Whether the service disappeared again within minutes.

Often benign when:
- Installers and management agents register their own services from Program Files.
