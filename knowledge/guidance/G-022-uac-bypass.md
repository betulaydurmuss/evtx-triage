---
id: G-022
title: User Account Control bypass
applies_to:
  events: []
  techniques:
  - T1548
  - T1548.002
  tactics:
  - Privilege Escalation
  - Stealth
sources:
- https://attack.mitre.org/techniques/T1548
- https://attack.mitre.org/techniques/T1548/002
---

A UAC bypass starts a high-integrity process from a medium-integrity session without a consent prompt, usually by abusing an auto-elevating Windows binary.

Check next:
- A process with IntegrityLevel High whose parent runs at Medium, with no consent.exe prompt in between.
- Auto-elevating binaries (fodhelper.exe, eventvwr.exe, computerdefaults.exe, sdclt.exe) launching unexpected children.
- Registry values written under HKCU ...\Classes\ms-settings or mscfile shortly before, or DLLs dropped next to an auto-elevating binary.
- Known bypass tooling in file or process names.

Often benign when:
- The user approved an elevation prompt; consent.exe is involved and the parent is an installer.
