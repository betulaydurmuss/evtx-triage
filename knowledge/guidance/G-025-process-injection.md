---
id: G-025
title: Code injection into another process
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:8
  - Microsoft-Windows-Sysmon/Operational:10
  techniques:
  - T1055
  tactics:
  - Stealth
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-8-createremotethread
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess
- https://attack.mitre.org/techniques/T1055
---

Injection runs attacker code inside another, usually trusted, process. Remote thread creation and write access to another process are the typical traces.

Check next:
- Sysmon 8: which SourceImage created a thread in which TargetImage, and whether StartModule is empty, meaning code outside any loaded module.
- Sysmon 10 with write and thread-creation rights (PROCESS_VM_WRITE 0x0020, PROCESS_CREATE_THREAD 0x0002) against a process other than LSASS.
- Network activity or child processes from the target process afterwards.

Often benign when:
- Debuggers, accessibility tools and some security products create threads in other processes.
