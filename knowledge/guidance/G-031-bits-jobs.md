---
id: G-031
title: BITS transfer jobs
applies_to:
  events:
  - Microsoft-Windows-Bits-Client/Operational:59
  techniques:
  - T1197
  - T1105
  tactics:
  - Command and Control
  - Persistence
  - Stealth
sources:
- https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal
- https://attack.mitre.org/techniques/T1197
- https://attack.mitre.org/techniques/T1105
---

BITS downloads and uploads files on behalf of other programs and keeps jobs alive across reboots. Updaters use it constantly, which is exactly why it hides a download well.

Check next:
- url: raw IP addresses, unfamiliar domains, or plain http to a host that is not an update service.
- name: jobs named after temporary files or executables, or created by bitsadmin or Start-BitsTransfer.
- What happens to the downloaded file next: execution, a scheduled task or a service pointing at it.

Often benign when:
- Windows Update, the Store, browsers and vendor updaters fetch from their own domains.
