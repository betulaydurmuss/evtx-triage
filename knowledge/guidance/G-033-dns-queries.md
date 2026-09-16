---
id: G-033
title: DNS queries by unusual processes
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:22
  techniques:
  - T1071
  - T1071.004
  tactics:
  - Command and Control
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query
- https://attack.mitre.org/techniques/T1071
- https://attack.mitre.org/techniques/T1071/004
---

DNS records tie a looked-up name to the process that asked for it. A name resolved by a script host, an unsigned binary or a tool in a temporary folder is a lead to the infrastructure behind an intrusion.

Check next:
- Image: which process made the query, and whether browsers or updaters would normally do so.
- QueryName: newly seen domains, long random-looking labels, dynamic DNS providers.
- QueryResults: whether the answers match later network connections.

Often benign when:
- Browsers, mail clients and update services resolve their usual domains.
