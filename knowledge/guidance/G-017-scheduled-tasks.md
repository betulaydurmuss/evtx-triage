---
id: G-017
title: Scheduled task created or changed
applies_to:
  events:
  - Security:4698
  - Security:4702
  - Security:4699
  techniques:
  - T1053
  - T1053.005
  tactics:
  - Execution
  - Persistence
  - Privilege Escalation
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699
- https://attack.mitre.org/techniques/T1053
- https://attack.mitre.org/techniques/T1053/005
---

A scheduled task runs a command on a trigger, optionally as SYSTEM. It is used both to execute once on a remote host and to persist.

Check next:
- The action in TaskContent: script hosts, encoded commands, binaries in user or temporary folders.
- The run-as account and the trigger (at logon, at startup, every few minutes).
- Tasks created and deleted within minutes, which suggests one-off remote execution.
- Task names that imitate Windows or vendor tasks.

Often benign when:
- Software updaters register tasks that point into Program Files.
