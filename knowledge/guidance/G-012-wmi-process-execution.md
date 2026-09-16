---
id: G-012
title: Processes started through WMI
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:1
  - Security:4688
  techniques:
  - T1047
  tactics:
  - Execution
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- https://attack.mitre.org/techniques/T1047
---

WmiPrvSE.exe is the WMI provider host. When it is the parent of cmd.exe, powershell or an unfamiliar binary, a command was most likely run through WMI, often from another host.

Check next:
- ParentImage WmiPrvSE.exe with a shell or script host as the child, and its full CommandLine.
- A network logon (4624 LogonType 3) for the same account shortly before.
- Output redirected to a file under ADMIN$ or C$, which is how some remote WMI tools read results back.

Often benign when:
- Inventory or monitoring software runs known scripts through WMI on a schedule.
