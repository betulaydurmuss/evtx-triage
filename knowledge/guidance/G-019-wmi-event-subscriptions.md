---
id: G-019
title: WMI event subscriptions
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:19
  - Microsoft-Windows-Sysmon/Operational:20
  - Microsoft-Windows-Sysmon/Operational:21
  techniques:
  - T1546
  - T1546.003
  tactics:
  - Persistence
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-19-wmievent-wmieventfilter-activity-detected
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-20-wmievent-wmieventconsumer-activity-detected
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-21-wmievent-wmieventconsumertofilter-activity-detected
- https://attack.mitre.org/techniques/T1546
- https://attack.mitre.org/techniques/T1546/003
---

A WMI event subscription runs a command when a condition is met. It survives reboots, runs as SYSTEM and leaves nothing in the usual startup locations.

Check next:
- Sysmon 20 consumer Destination: the command line or script that will run.
- Sysmon 19 filter Query: what triggers it, for example a timer or a process start.
- Sysmon 21 binding: the moment the subscription is armed. All three close together is the complete pattern.

Often benign when:
- A management or monitoring product registers a documented subscription.
