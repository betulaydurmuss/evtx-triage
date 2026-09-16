---
id: G-018
title: Autostart registry entries
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:13
  - Microsoft-Windows-Sysmon/Operational:12
  techniques:
  - T1547
  - T1547.001
  - T1112
  tactics:
  - Persistence
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-13-registryevent-value-set
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-12-registryevent-object-create-and-delete
- https://attack.mitre.org/techniques/T1547
- https://attack.mitre.org/techniques/T1547/001
- https://attack.mitre.org/techniques/T1112
---

Values under the Run and RunOnce keys start a program at logon. They are among the simplest and most common persistence mechanisms.

Check next:
- TargetObject under ...\CurrentVersion\Run or RunOnce (HKCU or HKLM) and the program in Details.
- Programs in user or temporary folders, script hosts with arguments, names imitating Windows components.
- Which process wrote the value, and whether that process was itself suspicious.

Often benign when:
- An installed application registers its own updater or tray program.
