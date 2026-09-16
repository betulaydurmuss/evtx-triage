---
id: G-002
title: Memory dump files written to disk
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:11
  techniques:
  - T1003.001
  tactics:
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate
- https://attack.mitre.org/techniques/T1003/001
---

A process created a memory dump file. When the dump is of lsass.exe it holds credential material that can be copied off the host and read offline.

Check next:
- TargetFilename and the writing Image: a .dmp written by an unfamiliar tool, by rundll32 loading comsvcs.dll, or into Windows\Temp or a user folder.
- An earlier access to lsass.exe by the same process id.
- Whether the file was then compressed, copied to a share, deleted, or followed by an outbound connection.

Often benign when:
- Windows Error Reporting or a debugger writes a crash dump of an application that really crashed.
