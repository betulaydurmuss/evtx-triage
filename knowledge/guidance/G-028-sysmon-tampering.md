---
id: G-028
title: Sysmon stopped or reconfigured
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:4
  - Microsoft-Windows-Sysmon/Operational:16
  techniques:
  - T1685
  - T1562
  - T1562.001
  tactics:
  - Defense Impairment
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-4-sysmon-service-state-changed
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-16-serviceconfigurationchange
- https://attack.mitre.org/techniques/T1685
---

Stopping Sysmon or loading a narrower configuration removes visibility on the host from that moment on.

Check next:
- Sysmon 4 with the service state Stopped outside planned maintenance.
- Sysmon 16 configuration changes: who made them, and whether the new configuration drops process, network or registry events.
- Activity immediately before and after the gap, in other log sources.

Often benign when:
- A planned Sysmon upgrade or configuration rollout, where a stop and a start appear close together.
