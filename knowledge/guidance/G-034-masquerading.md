---
id: G-034
title: Programs imitating Windows components
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:1
  techniques:
  - T1036
  - T1036.005
  tactics:
  - Stealth
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
- https://attack.mitre.org/techniques/T1036
- https://attack.mitre.org/techniques/T1036/005
---

Malware often uses names like svchost.exe, lsass.exe or explorer.exe so it does not stand out in a process list. The name alone is not the evidence; the location and the parent are.

Check next:
- Image path: system binary names outside System32 or SysWOW64, or in user and temporary folders.
- ParentImage: svchost.exe not started by services.exe, or lsass.exe with any parent other than wininit.exe.
- OriginalFileName and Hashes that do not match the real Windows binary.

Often benign when:
- Rarely for core system names; some software ships helper processes with similar names in its own folder.
