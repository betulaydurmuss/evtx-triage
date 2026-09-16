---
id: G-014
title: PowerShell script block content
applies_to:
  events:
  - Microsoft-Windows-PowerShell/Operational:4104
  techniques:
  - T1059
  - T1059.001
  tactics:
  - Execution
sources:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- https://attack.mitre.org/techniques/T1059
- https://attack.mitre.org/techniques/T1059/001
---

Script block logging records the code PowerShell actually ran, after decoding. The script text is the evidence; read it rather than judging by the process name.

Check next:
- Downloads followed by in-memory execution (Net.WebClient, DownloadString, Invoke-Expression, IEX).
- Base64 decoding (FromBase64String), compression streams and heavy string concatenation used for obfuscation.
- References to AMSI, reflection-based loading or offensive module names.
- Large scripts span several records with the same ScriptBlockId; read them together.

Often benign when:
- Administration or deployment scripts from known paths, logged at the same times every day.
