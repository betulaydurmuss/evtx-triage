---
id: G-006
title: Logons that suggest pass-the-hash or overpass-the-hash
applies_to:
  events:
  - Security:4624
  - Security:4648
  techniques:
  - T1550
  - T1550.002
  tactics:
  - Lateral Movement
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648
- https://attack.mitre.org/techniques/T1550
- https://attack.mitre.org/techniques/T1550/002
---

Stolen NTLM hashes or Kerberos keys can be used to authenticate without the password. On the host where the tool runs this often shows up as a new-credentials logon.

Check next:
- LogonType 9 (NewCredentials) with LogonProcessName seclogo, the shape produced when a process is started with injected credentials.
- Network logons (LogonType 3) over NTLM from hosts that normally use Kerberos.
- Whether the same account then reaches shares or other hosts.
- Credential access earlier on the same host, such as LSASS access or dump files.

Often benign when:
- An administrator deliberately uses runas /netonly, which also produces LogonType 9.
