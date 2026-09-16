---
id: G-003
title: Kerberos service ticket requests (possible Kerberoasting)
applies_to:
  events:
  - Security:4769
  techniques:
  - T1558
  - T1558.003
  tactics:
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- https://attack.mitre.org/techniques/T1558
- https://attack.mitre.org/techniques/T1558/003
---

A service ticket was requested for a service principal name. Any domain user can request one, and tickets encrypted with RC4 can be cracked offline to recover the service account password.

Check next:
- TicketEncryptionType 0x17 (RC4-HMAC) in an environment that normally uses AES (0x11, 0x12).
- Many different ServiceName values requested by one account within minutes.
- Whether the targeted services run under user accounts, whose passwords are the ones worth cracking.

Often benign when:
- A single AES-encrypted request for a service the account actually uses.
