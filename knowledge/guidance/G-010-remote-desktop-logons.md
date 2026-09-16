---
id: G-010
title: Remote Desktop logons
applies_to:
  events:
  - Security:4624
  techniques:
  - T1021
  - T1021.001
  tactics:
  - Lateral Movement
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- https://attack.mitre.org/techniques/T1021
- https://attack.mitre.org/techniques/T1021/001
---

A RemoteInteractive logon (LogonType 10) means someone signed in over Remote Desktop and received a full interactive session.

Check next:
- IpAddress: is the source a jump host or management network, or an ordinary workstation?
- Whether the account normally uses Remote Desktop to this host, and the time of day.
- Processes started in the session afterwards, especially through explorer.exe or the Run dialog.

Often benign when:
- Administrators connect from a documented jump server.
