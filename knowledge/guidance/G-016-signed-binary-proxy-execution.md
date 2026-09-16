---
id: G-016
title: Signed Windows binaries used to run other code (mshta, rundll32, regsvr32)
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:1
  - Security:4688
  techniques:
  - T1218
  - T1218.005
  - T1218.010
  - T1218.011
  tactics:
  - Stealth
  - Execution
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- https://attack.mitre.org/techniques/T1218
- https://attack.mitre.org/techniques/T1218/005
- https://attack.mitre.org/techniques/T1218/010
- https://attack.mitre.org/techniques/T1218/011
---

mshta.exe, rundll32.exe and regsvr32.exe are signed Windows binaries that can load and run scripts or DLLs, so the process doing the work looks trusted.

Check next:
- mshta with an http or https URL, or with inline javascript or vbscript.
- rundll32 with javascript:, RunHTMLApplication, a DLL in a user or temporary folder, or comsvcs.dll MiniDump (an LSASS dump).
- regsvr32 with /i: and a URL, or loading scrobj.dll.
- Network connections from these processes and the files they create.

Often benign when:
- rundll32 loads DLLs from System32 with known entry points, as Control Panel items do.
