---
id: G-023
title: Token impersonation through named pipes (potato exploits)
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:17
  - Microsoft-Windows-Sysmon/Operational:18
  techniques:
  - T1134
  - T1134.001
  - T1068
  tactics:
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-17-pipeevent-pipe-created
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-18-pipeevent-pipe-connected
- https://attack.mitre.org/techniques/T1134
- https://attack.mitre.org/techniques/T1134/001
- https://attack.mitre.org/techniques/T1068
---

Service accounts such as LOCAL SERVICE and NETWORK SERVICE hold the impersonation privilege. "Potato" exploits make a SYSTEM process connect to a named pipe they control and then impersonate its token.

Check next:
- A process running as LOCAL SERVICE or NETWORK SERVICE, often a web or database worker, creating a named pipe (Sysmon 17) that a SYSTEM process then connects to (Sysmon 18).
- A shell or network tool (cmd.exe, nc.exe) started as SYSTEM right afterwards.
- How the service account process got its payload in the first place, for example through a web shell.

Often benign when:
- Rarely: named pipes are normal, but service-account processes spawning SYSTEM shells are not.
