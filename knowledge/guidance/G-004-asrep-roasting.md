---
id: G-004
title: Kerberos TGT requests without pre-authentication
applies_to:
  events:
  - Security:4768
  techniques:
  - T1558
  - T1558.004
  tactics:
  - Credential Access
sources:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
- https://attack.mitre.org/techniques/T1558
- https://attack.mitre.org/techniques/T1558/004
---

A domain controller handled a TGT request. For accounts that do not require Kerberos pre-authentication, anyone can request a TGT without the password and crack the encrypted part offline.

Check next:
- PreAuthType 0 (no pre-authentication) together with TicketEncryptionType 0x17.
- The requesting IpAddress, and requests for several accounts in a row.
- Whether "do not require Kerberos pre-authentication" is intentionally set on the account.

Often benign when:
- Pre-authentication is present and the request comes from the account's usual workstation.
