---
id: G-029
title: Microsoft Defender detections
applies_to:
  events:
  - Microsoft-Windows-Windows Defender/Operational:1116
  techniques:
  - T1204
  - T1105
  tactics: []
sources:
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
- https://attack.mitre.org/techniques/T1204
- https://attack.mitre.org/techniques/T1105
---

Defender reported malware or unwanted software. A detection shows what was seen, not that it was stopped.

Check next:
- Threat Name, Severity and Path: what was detected and where it was written or run from.
- Whether a remediation record (event 1117) follows, and whether the action succeeded.
- Process Name and Detection User: how the file arrived, through a browser, mail client, archive tool or script host.
- The same path or file on other hosts.

Often benign when:
- Test files, or potentially unwanted software flagged in a download folder and removed.
