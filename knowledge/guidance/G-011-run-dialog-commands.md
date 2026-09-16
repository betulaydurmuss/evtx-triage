---
id: G-011
title: Commands entered through the Run dialog
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:12
  - Microsoft-Windows-Sysmon/Operational:13
  techniques:
  - T1021.001
  - T1059
  - T1070
  tactics:
  - Execution
  - Lateral Movement
  - Stealth
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-12-registryevent-object-create-and-delete
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-13-registryevent-value-set
- https://attack.mitre.org/techniques/T1021/001
- https://attack.mitre.org/techniques/T1059
- https://attack.mitre.org/techniques/T1070
---

explorer.exe records commands typed into the Run dialog under the RunMRU registry key. Tools that drive a remote desktop session programmatically type commands this way, and some delete the RunMRU entries afterwards to hide them.

Check next:
- Sysmon 13 values written under ...\Explorer\RunMRU; the Details field holds the command.
- Sysmon 12 deletions of RunMRU keys soon after, which suggest clean-up.
- A remote desktop logon for the same account just before, and the processes started right after.

Often benign when:
- A user typed into Win+R themselves: no deletion follows and there is no preceding remote logon.
