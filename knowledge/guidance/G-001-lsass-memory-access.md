---
id: G-001
title: Access to LSASS process memory
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:10
  techniques:
  - T1003
  - T1003.001
  tactics:
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess
- https://attack.mitre.org/techniques/T1003
- https://attack.mitre.org/techniques/T1003/001
---

A process opened a handle to lsass.exe. LSASS holds credential material for signed-in users, so a handle that can read its memory is the central step of most credential dumping tools.

Check next:
- Which image opened the handle (SourceImage), where it lives and whether it is signed. Tools running from user profiles, temporary folders or network shares are the strongest signal.
- The requested rights (GrantedAccess). Masks that include PROCESS_VM_READ (0x0010) allow memory reads; full access (0x1fffff) is common for dumping tools.
- A file written by the same process shortly afterwards, especially with a .dmp extension.
- The account and logon session that started the source process.

Often benign when:
- The source is an endpoint security product, a crash reporter, or a Windows component asking for a narrow access mask.
