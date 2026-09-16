---
id: G-024
title: Event logs cleared
applies_to:
  events:
  - Security:1102
  - System:104
  techniques:
  - T1685
  - T1685.005
  - T1070
  - T1070.001
  tactics:
  - Defense Impairment
  - Stealth
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
- https://attack.mitre.org/techniques/T1685
- https://attack.mitre.org/techniques/T1685/005
- https://attack.mitre.org/techniques/T1070
---

Clearing an event log removes the record of what happened before it. It rarely has a legitimate reason on a production host and marks the point where the investigation needs other sources.

Check next:
- Which account cleared the log (SubjectUserName) and from which logon session.
- What happened immediately before the clear, on this host and on hosts the same account reached.
- Whether other logs were cleared or logging was reconfigured at the same time.
- Evidence outside the host: forwarded logs, endpoint telemetry, network records.

Often benign when:
- A documented maintenance procedure or a lab reset.
