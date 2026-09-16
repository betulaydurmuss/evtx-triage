---
id: G-015
title: Suspicious command lines and shells
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:1
  - Security:4688
  techniques:
  - T1059
  - T1059.001
  - T1059.003
  - T1027
  tactics:
  - Execution
  - Stealth
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- https://attack.mitre.org/techniques/T1059
- https://attack.mitre.org/techniques/T1059/001
- https://attack.mitre.org/techniques/T1059/003
- https://attack.mitre.org/techniques/T1027
---

Most attacker activity eventually runs a command. The command line and the parent-child relationship usually say more than the binary name.

Check next:
- Encoded or obfuscated arguments: -enc, long base64 strings, carets or quotes inserted inside words.
- Unusual parents: Office applications, browsers, script hosts or services starting cmd.exe or powershell.
- Binaries running from user profiles, temporary folders, the recycle bin or network shares.
- Reconnaissance commands in quick succession (whoami, net group, nltest, ipconfig).

Often benign when:
- The same command line appears on many hosts, launched by a management tool.
