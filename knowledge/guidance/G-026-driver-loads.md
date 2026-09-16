---
id: G-026
title: Kernel drivers loaded
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:6
  techniques:
  - T1068
  - T1543.003
  - T1685
  tactics:
  - Privilege Escalation
  - Defense Impairment
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-6-driver-loaded
- https://attack.mitre.org/techniques/T1068
- https://attack.mitre.org/techniques/T1543/003
- https://attack.mitre.org/techniques/T1685
---

A driver runs in the kernel. Attackers load vulnerable signed drivers to switch off security tools, or unsigned drivers where signature enforcement is weak.

Check next:
- Signed and SignatureStatus: unsigned drivers, or valid signatures from unexpected publishers.
- ImageLoaded paths outside System32\drivers, especially user or temporary folders.
- Security product processes stopping shortly after the load.

Often benign when:
- Hardware or security software drivers with a valid signature, loaded from their installed location.
