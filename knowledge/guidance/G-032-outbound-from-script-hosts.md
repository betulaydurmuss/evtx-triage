---
id: G-032
title: Network connections from script hosts and proxy binaries
applies_to:
  events:
  - Microsoft-Windows-Sysmon/Operational:3
  - Security:5156
  techniques:
  - T1071
  - T1071.001
  - T1105
  tactics:
  - Command and Control
sources:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-3-network-connection
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156
- https://attack.mitre.org/techniques/T1071
- https://attack.mitre.org/techniques/T1071/001
- https://attack.mitre.org/techniques/T1105
---

powershell, mshta, rundll32, regsvr32, wscript and cscript rarely need to connect out on their own. A connection from one of them is often a payload being fetched or a command channel starting.

Check next:
- Image with DestinationIp or DestinationHostname: script hosts reaching external or unusual internal addresses.
- The command line of that process and the files it created afterwards.
- Repeated connections at regular intervals, which suggest beaconing.

Often benign when:
- Management scripts reach internal servers, or certificate checks go to well-known vendor endpoints.
