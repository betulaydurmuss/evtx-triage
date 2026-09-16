---
id: G-027
title: File creation time changed (timestomping)
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:2
  techniques:
  - T1070
  - T1070.006
  tactics:
  - Stealth
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-2-a-process-changed-a-file-creation-time
- https://attack.mitre.org/techniques/T1070
- https://attack.mitre.org/techniques/T1070/006
---

Changing a file's creation time makes a dropped file look older, so it blends in with system files during a timeline review.

Check next:
- PreviousCreationUtcTime against CreationUtcTime: a new timestamp far in the past.
- The process that made the change, and whether it also created the file.
- Executables or DLLs affected, especially in system folders.

Often benign when:
- Installers, archive extractors and synchronisation clients preserving original timestamps.
