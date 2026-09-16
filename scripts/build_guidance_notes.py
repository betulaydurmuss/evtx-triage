"""Write the investigation guidance notes (knowledge/guidance/G-*.md).

Note text is authored here in our own words. Sources are NOT typed by hand: they
are derived from data that was already verified, so a note cannot cite a URL
nobody checked:

- for every `Channel:EventID` a note applies to, the first source of that
  dictionary entry (each dictionary URL was checked to return HTTP 200);
- for every technique id that is current in the pinned ATT&CK catalogue, the
  technique page URL carried by the catalogue itself.

Retired ATT&CK ids (for example T1070.001, now T1685.005) stay in `applies_to`
because Sigma rules still emit them and the pre-filter must match what the
timeline actually contains, but they are never cited as sources.

    python scripts/build_guidance_notes.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SYSMON = "Microsoft-Windows-Sysmon/Operational"

NOTES: list[dict[str, object]] = [
    {
        "id": "G-001",
        "slug": "lsass-memory-access",
        "title": "Access to LSASS process memory",
        "events": [f"{SYSMON}:10"],
        "techniques": ["T1003", "T1003.001"],
        "tactics": ["Credential Access"],
        "body": """A process opened a handle to lsass.exe. LSASS holds credential material for signed-in users, so a handle that can read its memory is the central step of most credential dumping tools.

Check next:
- Which image opened the handle (SourceImage), where it lives and whether it is signed. Tools running from user profiles, temporary folders or network shares are the strongest signal.
- The requested rights (GrantedAccess). Masks that include PROCESS_VM_READ (0x0010) allow memory reads; full access (0x1fffff) is common for dumping tools.
- A file written by the same process shortly afterwards, especially with a .dmp extension.
- The account and logon session that started the source process.

Often benign when:
- The source is an endpoint security product, a crash reporter, or a Windows component asking for a narrow access mask.""",
    },
    {
        "id": "G-002",
        "slug": "memory-dump-files",
        "title": "Memory dump files written to disk",
        "events": [f"{SYSMON}:11"],
        "techniques": ["T1003.001"],
        "tactics": ["Credential Access"],
        "body": """A process created a memory dump file. When the dump is of lsass.exe it holds credential material that can be copied off the host and read offline.

Check next:
- TargetFilename and the writing Image: a .dmp written by an unfamiliar tool, by rundll32 loading comsvcs.dll, or into Windows\\Temp or a user folder.
- An earlier access to lsass.exe by the same process id.
- Whether the file was then compressed, copied to a share, deleted, or followed by an outbound connection.

Often benign when:
- Windows Error Reporting or a debugger writes a crash dump of an application that really crashed.""",
    },
    {
        "id": "G-003",
        "slug": "kerberoasting",
        "title": "Kerberos service ticket requests (possible Kerberoasting)",
        "events": ["Security:4769"],
        "techniques": ["T1558", "T1558.003"],
        "tactics": ["Credential Access"],
        "body": """A service ticket was requested for a service principal name. Any domain user can request one, and tickets encrypted with RC4 can be cracked offline to recover the service account password.

Check next:
- TicketEncryptionType 0x17 (RC4-HMAC) in an environment that normally uses AES (0x11, 0x12).
- Many different ServiceName values requested by one account within minutes.
- Whether the targeted services run under user accounts, whose passwords are the ones worth cracking.

Often benign when:
- A single AES-encrypted request for a service the account actually uses.""",
    },
    {
        "id": "G-004",
        "slug": "asrep-roasting",
        "title": "Kerberos TGT requests without pre-authentication",
        "events": ["Security:4768"],
        "techniques": ["T1558", "T1558.004"],
        "tactics": ["Credential Access"],
        "body": """A domain controller handled a TGT request. For accounts that do not require Kerberos pre-authentication, anyone can request a TGT without the password and crack the encrypted part offline.

Check next:
- PreAuthType 0 (no pre-authentication) together with TicketEncryptionType 0x17.
- The requesting IpAddress, and requests for several accounts in a row.
- Whether "do not require Kerberos pre-authentication" is intentionally set on the account.

Often benign when:
- Pre-authentication is present and the request comes from the account's usual workstation.""",
    },
    {
        "id": "G-005",
        "slug": "password-guessing",
        "title": "Repeated authentication failures (password guessing or spraying)",
        "events": ["Security:4625", "Security:4776"],
        "techniques": ["T1110", "T1110.001", "T1110.003"],
        "tactics": ["Credential Access"],
        "body": """Logon or credential validation attempts failed. The pattern across events matters more than any single failure.

Check next:
- Many failures for one account from one source: password guessing.
- One or two failures each for many accounts from one source: password spraying.
- Status and SubStatus, which separate wrong passwords from unknown, disabled or locked accounts.
- A successful logon (4624) for the same account or source right after the failures.

Often benign when:
- A user with an expired password, or a service with a stale stored credential, fails repeatedly from its usual host.""",
    },
    {
        "id": "G-006",
        "slug": "pass-the-hash",
        "title": "Logons that suggest pass-the-hash or overpass-the-hash",
        "events": ["Security:4624", "Security:4648"],
        "techniques": ["T1550", "T1550.002"],
        "tactics": ["Lateral Movement", "Credential Access"],
        "body": """Stolen NTLM hashes or Kerberos keys can be used to authenticate without the password. On the host where the tool runs this often shows up as a new-credentials logon.

Check next:
- LogonType 9 (NewCredentials) with LogonProcessName seclogo, the shape produced when a process is started with injected credentials.
- Network logons (LogonType 3) over NTLM from hosts that normally use Kerberos.
- Whether the same account then reaches shares or other hosts.
- Credential access earlier on the same host, such as LSASS access or dump files.

Often benign when:
- An administrator deliberately uses runas /netonly, which also produces LogonType 9.""",
    },
    {
        "id": "G-007",
        "slug": "dcsync",
        "title": "Directory replication rights and DCSync",
        "events": ["Security:4662", "Security:5136"],
        "techniques": ["T1003", "T1003.006", "T1098"],
        "tactics": ["Credential Access", "Persistence"],
        "body": """An account with directory replication rights can ask a domain controller for the password data of any account, without running code on the domain controller.

Check next:
- 4662 events whose properties include DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) or DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2), requested by an account that is not a domain controller.
- 5136 changes to the domain object's security descriptor that grant those rights to an ordinary account.
- Who made the change, from which session, and whether the log was cleared afterwards.

Often benign when:
- The requester is a domain controller computer account or a documented directory synchronisation service.""",
    },
    {
        "id": "G-008",
        "slug": "service-installation",
        "title": "Service installed on a host (remote execution or persistence)",
        "events": ["System:7045"],
        "techniques": ["T1569", "T1569.002", "T1543", "T1543.003"],
        "tactics": ["Execution", "Persistence"],
        "body": """A new service was registered. Remote execution tools create a short-lived service to run one command; persistence installs a long-lived one.

Check next:
- ImagePath: commands through cmd.exe or powershell, encoded arguments, binaries in temporary or share paths, random-looking service names.
- AccountName: a service running as LocalSystem has full control of the host.
- A network logon and ADMIN$ share access from another host just before, which points to remote execution.
- Whether the service disappeared again within minutes.

Often benign when:
- Installers and management agents register their own services from Program Files.""",
    },
    {
        "id": "G-009",
        "slug": "admin-share-access",
        "title": "Administrative share access",
        "events": ["Security:5140", "Security:5145"],
        "techniques": ["T1021", "T1021.002"],
        "tactics": ["Lateral Movement"],
        "body": """A client connected to a share on this host. Access to ADMIN$, C$ or IPC$ from another machine is the usual first step of remote execution over SMB.

Check next:
- ShareName, and for 5145 the RelativeTargetName: executables or scripts copied into ADMIN$ or C$\\Windows.
- The source IpAddress and account, and whether that host normally administers this one.
- A service installation, scheduled task or new process shortly after the access.

Often benign when:
- Management, deployment and backup servers routinely read administrative shares.""",
    },
    {
        "id": "G-010",
        "slug": "remote-desktop-logons",
        "title": "Remote Desktop logons",
        "events": ["Security:4624"],
        "techniques": ["T1021", "T1021.001"],
        "tactics": ["Lateral Movement"],
        "body": """A RemoteInteractive logon (LogonType 10) means someone signed in over Remote Desktop and received a full interactive session.

Check next:
- IpAddress: is the source a jump host or management network, or an ordinary workstation?
- Whether the account normally uses Remote Desktop to this host, and the time of day.
- Processes started in the session afterwards, especially through explorer.exe or the Run dialog.

Often benign when:
- Administrators connect from a documented jump server.""",
    },
    {
        "id": "G-011",
        "slug": "run-dialog-commands",
        "title": "Commands entered through the Run dialog",
        "events": [f"{SYSMON}:12", f"{SYSMON}:13"],
        "techniques": ["T1021.001", "T1059", "T1070"],
        "tactics": ["Execution", "Lateral Movement", "Stealth"],
        "body": """explorer.exe records commands typed into the Run dialog under the RunMRU registry key. Tools that drive a remote desktop session programmatically type commands this way, and some delete the RunMRU entries afterwards to hide them.

Check next:
- Sysmon 13 values written under ...\\Explorer\\RunMRU; the Details field holds the command.
- Sysmon 12 deletions of RunMRU keys soon after, which suggest clean-up.
- A remote desktop logon for the same account just before, and the processes started right after.

Often benign when:
- A user typed into Win+R themselves: no deletion follows and there is no preceding remote logon.""",
    },
    {
        "id": "G-012",
        "slug": "wmi-process-execution",
        "title": "Processes started through WMI",
        "events": [f"{SYSMON}:1", "Security:4688"],
        "techniques": ["T1047"],
        "tactics": ["Execution"],
        "body": """WmiPrvSE.exe is the WMI provider host. When it is the parent of cmd.exe, powershell or an unfamiliar binary, a command was most likely run through WMI, often from another host.

Check next:
- ParentImage WmiPrvSE.exe with a shell or script host as the child, and its full CommandLine.
- A network logon (4624 LogonType 3) for the same account shortly before.
- Output redirected to a file under ADMIN$ or C$, which is how some remote WMI tools read results back.

Often benign when:
- Inventory or monitoring software runs known scripts through WMI on a schedule.""",
    },
    {
        "id": "G-013",
        "slug": "explicit-credentials",
        "title": "Logons with explicitly supplied credentials",
        "events": ["Security:4648"],
        "techniques": ["T1078"],
        "tactics": ["Lateral Movement", "Privilege Escalation"],
        "body": """A process supplied another account's credentials instead of using its own token. That is normal for runas and scheduled tasks, and it is also the footprint of lateral movement tools connecting with stolen credentials.

Check next:
- The calling account (Subject) against the credentials used (Target): an ordinary user supplying an administrator's credentials.
- TargetServerName: connections to many hosts in a short time.
- ProcessName: tools running from user or temporary folders.

Often benign when:
- A scheduled task or service uses a stored service account and targets the same server every time.""",
    },
    {
        "id": "G-014",
        "slug": "powershell-script-blocks",
        "title": "PowerShell script block content",
        "events": ["Microsoft-Windows-PowerShell/Operational:4104"],
        "techniques": ["T1059", "T1059.001"],
        "tactics": ["Execution"],
        "body": """Script block logging records the code PowerShell actually ran, after decoding. The script text is the evidence; read it rather than judging by the process name.

Check next:
- Downloads followed by in-memory execution (Net.WebClient, DownloadString, Invoke-Expression, IEX).
- Base64 decoding (FromBase64String), compression streams and heavy string concatenation used for obfuscation.
- References to AMSI, reflection-based loading or offensive module names.
- Large scripts span several records with the same ScriptBlockId; read them together.

Often benign when:
- Administration or deployment scripts from known paths, logged at the same times every day.""",
    },
    {
        "id": "G-015",
        "slug": "suspicious-command-lines",
        "title": "Suspicious command lines and shells",
        "events": [f"{SYSMON}:1", "Security:4688"],
        "techniques": ["T1059", "T1059.001", "T1059.003", "T1027"],
        "tactics": ["Execution", "Stealth"],
        "body": """Most attacker activity eventually runs a command. The command line and the parent-child relationship usually say more than the binary name.

Check next:
- Encoded or obfuscated arguments: -enc, long base64 strings, carets or quotes inserted inside words.
- Unusual parents: Office applications, browsers, script hosts or services starting cmd.exe or powershell.
- Binaries running from user profiles, temporary folders, the recycle bin or network shares.
- Reconnaissance commands in quick succession (whoami, net group, nltest, ipconfig).

Often benign when:
- The same command line appears on many hosts, launched by a management tool.""",
    },
    {
        "id": "G-016",
        "slug": "signed-binary-proxy-execution",
        "title": "Signed Windows binaries used to run other code (mshta, rundll32, regsvr32)",
        "events": [f"{SYSMON}:1", "Security:4688"],
        "techniques": ["T1218", "T1218.005", "T1218.010", "T1218.011"],
        "tactics": ["Stealth", "Execution"],
        "body": """mshta.exe, rundll32.exe and regsvr32.exe are signed Windows binaries that can load and run scripts or DLLs, so the process doing the work looks trusted.

Check next:
- mshta with an http or https URL, or with inline javascript or vbscript.
- rundll32 with javascript:, RunHTMLApplication, a DLL in a user or temporary folder, or comsvcs.dll MiniDump (an LSASS dump).
- regsvr32 with /i: and a URL, or loading scrobj.dll.
- Network connections from these processes and the files they create.

Often benign when:
- rundll32 loads DLLs from System32 with known entry points, as Control Panel items do.""",
    },
    {
        "id": "G-017",
        "slug": "scheduled-tasks",
        "title": "Scheduled task created or changed",
        "events": ["Security:4698", "Security:4702", "Security:4699"],
        "techniques": ["T1053", "T1053.005"],
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "body": """A scheduled task runs a command on a trigger, optionally as SYSTEM. It is used both to execute once on a remote host and to persist.

Check next:
- The action in TaskContent: script hosts, encoded commands, binaries in user or temporary folders.
- The run-as account and the trigger (at logon, at startup, every few minutes).
- Tasks created and deleted within minutes, which suggests one-off remote execution.
- Task names that imitate Windows or vendor tasks.

Often benign when:
- Software updaters register tasks that point into Program Files.""",
    },
    {
        "id": "G-018",
        "slug": "registry-autostart",
        "title": "Autostart registry entries",
        "events": [f"{SYSMON}:13", f"{SYSMON}:12"],
        "techniques": ["T1547", "T1547.001", "T1112"],
        "tactics": ["Persistence"],
        "body": """Values under the Run and RunOnce keys start a program at logon. They are among the simplest and most common persistence mechanisms.

Check next:
- TargetObject under ...\\CurrentVersion\\Run or RunOnce (HKCU or HKLM) and the program in Details.
- Programs in user or temporary folders, script hosts with arguments, names imitating Windows components.
- Which process wrote the value, and whether that process was itself suspicious.

Often benign when:
- An installed application registers its own updater or tray program.""",
    },
    {
        "id": "G-019",
        "slug": "wmi-event-subscriptions",
        "title": "WMI event subscriptions",
        "events": [f"{SYSMON}:19", f"{SYSMON}:20", f"{SYSMON}:21"],
        "techniques": ["T1546", "T1546.003"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "body": """A WMI event subscription runs a command when a condition is met. It survives reboots, runs as SYSTEM and leaves nothing in the usual startup locations.

Check next:
- Sysmon 20 consumer Destination: the command line or script that will run.
- Sysmon 19 filter Query: what triggers it, for example a timer or a process start.
- Sysmon 21 binding: the moment the subscription is armed. All three close together is the complete pattern.

Often benign when:
- A management or monitoring product registers a documented subscription.""",
    },
    {
        "id": "G-020",
        "slug": "accounts-and-group-membership",
        "title": "New accounts and privileged group membership",
        "events": ["Security:4720", "Security:4732", "Security:4781"],
        "techniques": ["T1136", "T1136.001", "T1098"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "body": """Creating an account, or adding one to a privileged group, gives an attacker access that no longer depends on the credentials they stole first.

Check next:
- 4732 additions to Administrators or Remote Desktop Users, and which account made them.
- 4720 accounts created outside the normal provisioning process; 4781 renames that make an account look like a service account.
- Whether the new account signs in soon afterwards, and from where.

Often benign when:
- Help desk or provisioning tooling creates accounts during working hours through a known administrative account.""",
    },
    {
        "id": "G-021",
        "slug": "computer-accounts-and-sid-history",
        "title": "Computer account changes and SID history",
        "events": ["Security:4741", "Security:4742", "Security:4765"],
        "techniques": ["T1098", "T1134"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "body": """New computer accounts, delegation changes and SID history additions are ways to gain rights in Active Directory without joining a privileged group.

Check next:
- 4741 computer accounts created by ordinary users, since any user can usually add a few.
- 4742 changes to delegation (AllowedToDelegateTo) or to service principal names.
- 4765 SID history added outside a planned domain migration.

Often benign when:
- IT staff join machines to the domain as part of normal provisioning.""",
    },
    {
        "id": "G-022",
        "slug": "uac-bypass",
        "title": "User Account Control bypass",
        "events": [],
        "techniques": ["T1548", "T1548.002"],
        "tactics": ["Privilege Escalation", "Stealth"],
        "body": """A UAC bypass starts a high-integrity process from a medium-integrity session without a consent prompt, usually by abusing an auto-elevating Windows binary.

Check next:
- A process with IntegrityLevel High whose parent runs at Medium, with no consent.exe prompt in between.
- Auto-elevating binaries (fodhelper.exe, eventvwr.exe, computerdefaults.exe, sdclt.exe) launching unexpected children.
- Registry values written under HKCU ...\\Classes\\ms-settings or mscfile shortly before, or DLLs dropped next to an auto-elevating binary.
- Known bypass tooling in file or process names.

Often benign when:
- The user approved an elevation prompt; consent.exe is involved and the parent is an installer.""",
    },
    {
        "id": "G-023",
        "slug": "named-pipe-impersonation",
        "title": "Token impersonation through named pipes (potato exploits)",
        "events": [f"{SYSMON}:17", f"{SYSMON}:18"],
        "techniques": ["T1134", "T1134.001", "T1068"],
        "tactics": ["Privilege Escalation"],
        "body": """Service accounts such as LOCAL SERVICE and NETWORK SERVICE hold the impersonation privilege. "Potato" exploits make a SYSTEM process connect to a named pipe they control and then impersonate its token.

Check next:
- A process running as LOCAL SERVICE or NETWORK SERVICE, often a web or database worker, creating a named pipe (Sysmon 17) that a SYSTEM process then connects to (Sysmon 18).
- A shell or network tool (cmd.exe, nc.exe) started as SYSTEM right afterwards.
- How the service account process got its payload in the first place, for example through a web shell.

Often benign when:
- Rarely: named pipes are normal, but service-account processes spawning SYSTEM shells are not.""",
    },
    {
        "id": "G-024",
        "slug": "event-log-clearing",
        "title": "Event logs cleared",
        "events": ["Security:1102", "System:104"],
        "techniques": ["T1685", "T1685.005", "T1070", "T1070.001"],
        "tactics": ["Defense Impairment", "Stealth"],
        "body": """Clearing an event log removes the record of what happened before it. It rarely has a legitimate reason on a production host and marks the point where the investigation needs other sources.

Check next:
- Which account cleared the log (SubjectUserName) and from which logon session.
- What happened immediately before the clear, on this host and on hosts the same account reached.
- Whether other logs were cleared or logging was reconfigured at the same time.
- Evidence outside the host: forwarded logs, endpoint telemetry, network records.

Often benign when:
- A documented maintenance procedure or a lab reset.""",
    },
    {
        "id": "G-025",
        "slug": "process-injection",
        "title": "Code injection into another process",
        "events": [f"{SYSMON}:8", f"{SYSMON}:10"],
        "techniques": ["T1055"],
        "tactics": ["Stealth", "Privilege Escalation"],
        "body": """Injection runs attacker code inside another, usually trusted, process. Remote thread creation and write access to another process are the typical traces.

Check next:
- Sysmon 8: which SourceImage created a thread in which TargetImage, and whether StartModule is empty, meaning code outside any loaded module.
- Sysmon 10 with write and thread-creation rights (PROCESS_VM_WRITE 0x0020, PROCESS_CREATE_THREAD 0x0002) against a process other than LSASS.
- Network activity or child processes from the target process afterwards.

Often benign when:
- Debuggers, accessibility tools and some security products create threads in other processes.""",
    },
    {
        "id": "G-026",
        "slug": "driver-loads",
        "title": "Kernel drivers loaded",
        "events": [f"{SYSMON}:6"],
        "techniques": ["T1068", "T1543.003", "T1685"],
        "tactics": ["Privilege Escalation", "Defense Impairment"],
        "body": """A driver runs in the kernel. Attackers load vulnerable signed drivers to switch off security tools, or unsigned drivers where signature enforcement is weak.

Check next:
- Signed and SignatureStatus: unsigned drivers, or valid signatures from unexpected publishers.
- ImageLoaded paths outside System32\\drivers, especially user or temporary folders.
- Security product processes stopping shortly after the load.

Often benign when:
- Hardware or security software drivers with a valid signature, loaded from their installed location.""",
    },
    {
        "id": "G-027",
        "slug": "timestomping",
        "title": "File creation time changed (timestomping)",
        "events": [f"{SYSMON}:2"],
        "techniques": ["T1070", "T1070.006"],
        "tactics": ["Stealth"],
        "body": """Changing a file's creation time makes a dropped file look older, so it blends in with system files during a timeline review.

Check next:
- PreviousCreationUtcTime against CreationUtcTime: a new timestamp far in the past.
- The process that made the change, and whether it also created the file.
- Executables or DLLs affected, especially in system folders.

Often benign when:
- Installers, archive extractors and synchronisation clients preserving original timestamps.""",
    },
    {
        "id": "G-028",
        "slug": "sysmon-tampering",
        "title": "Sysmon stopped or reconfigured",
        "events": [f"{SYSMON}:4", f"{SYSMON}:16"],
        "techniques": ["T1685", "T1562", "T1562.001"],
        "tactics": ["Defense Impairment"],
        "body": """Stopping Sysmon or loading a narrower configuration removes visibility on the host from that moment on.

Check next:
- Sysmon 4 with the service state Stopped outside planned maintenance.
- Sysmon 16 configuration changes: who made them, and whether the new configuration drops process, network or registry events.
- Activity immediately before and after the gap, in other log sources.

Often benign when:
- A planned Sysmon upgrade or configuration rollout, where a stop and a start appear close together.""",
    },
    {
        "id": "G-029",
        "slug": "defender-detections",
        "title": "Microsoft Defender detections",
        "events": ["Microsoft-Windows-Windows Defender/Operational:1116"],
        "techniques": ["T1204", "T1105"],
        "tactics": [],
        "body": """Defender reported malware or unwanted software. A detection shows what was seen, not that it was stopped.

Check next:
- Threat Name, Severity and Path: what was detected and where it was written or run from.
- Whether a remediation record (event 1117) follows, and whether the action succeeded.
- Process Name and Detection User: how the file arrived, through a browser, mail client, archive tool or script host.
- The same path or file on other hosts.

Often benign when:
- Test files, or potentially unwanted software flagged in a download folder and removed.""",
    },
    {
        "id": "G-030",
        "slug": "directory-enumeration",
        "title": "Active Directory account and group enumeration",
        "events": ["Security:4661", "Security:4662"],
        "techniques": ["T1087", "T1087.002", "T1069", "T1069.002", "T1201"],
        "tactics": ["Discovery"],
        "body": """Before moving laterally, attackers list domain administrators, privileged groups and the password policy. Directory and SAM access records show these queries.

Check next:
- 4661 handle requests on SAM objects such as the domain, Domain Admins or many user objects, from an account that is not a management server.
- A burst of queries within seconds, which suggests a tool rather than a person.
- The session source: a network logon and IPC$ share access just before.
- Password policy enumeration followed by authentication failures across many accounts.

Often benign when:
- Identity management, auditing or monitoring software enumerates groups on a schedule.""",
    },
    {
        "id": "G-031",
        "slug": "bits-jobs",
        "title": "BITS transfer jobs",
        "events": ["Microsoft-Windows-Bits-Client/Operational:59"],
        "techniques": ["T1197", "T1105"],
        "tactics": ["Command and Control", "Persistence", "Stealth"],
        "body": """BITS downloads and uploads files on behalf of other programs and keeps jobs alive across reboots. Updaters use it constantly, which is exactly why it hides a download well.

Check next:
- url: raw IP addresses, unfamiliar domains, or plain http to a host that is not an update service.
- name: jobs named after temporary files or executables, or created by bitsadmin or Start-BitsTransfer.
- What happens to the downloaded file next: execution, a scheduled task or a service pointing at it.

Often benign when:
- Windows Update, the Store, browsers and vendor updaters fetch from their own domains.""",
    },
    {
        "id": "G-032",
        "slug": "outbound-from-script-hosts",
        "title": "Network connections from script hosts and proxy binaries",
        "events": [f"{SYSMON}:3", "Security:5156"],
        "techniques": ["T1071", "T1071.001", "T1105"],
        "tactics": ["Command and Control"],
        "body": """powershell, mshta, rundll32, regsvr32, wscript and cscript rarely need to connect out on their own. A connection from one of them is often a payload being fetched or a command channel starting.

Check next:
- Image with DestinationIp or DestinationHostname: script hosts reaching external or unusual internal addresses.
- The command line of that process and the files it created afterwards.
- Repeated connections at regular intervals, which suggest beaconing.

Often benign when:
- Management scripts reach internal servers, or certificate checks go to well-known vendor endpoints.""",
    },
    {
        "id": "G-033",
        "slug": "dns-queries",
        "title": "DNS queries by unusual processes",
        "events": [f"{SYSMON}:22"],
        "techniques": ["T1071", "T1071.004"],
        "tactics": ["Command and Control"],
        "body": """DNS records tie a looked-up name to the process that asked for it. A name resolved by a script host, an unsigned binary or a tool in a temporary folder is a lead to the infrastructure behind an intrusion.

Check next:
- Image: which process made the query, and whether browsers or updaters would normally do so.
- QueryName: newly seen domains, long random-looking labels, dynamic DNS providers.
- QueryResults: whether the answers match later network connections.

Often benign when:
- Browsers, mail clients and update services resolve their usual domains.""",
    },
    {
        "id": "G-034",
        "slug": "masquerading",
        "title": "Programs imitating Windows components",
        "events": [f"{SYSMON}:1"],
        "techniques": ["T1036", "T1036.005"],
        "tactics": ["Stealth"],
        "body": """Malware often uses names like svchost.exe, lsass.exe or explorer.exe so it does not stand out in a process list. The name alone is not the evidence; the location and the parent are.

Check next:
- Image path: system binary names outside System32 or SysWOW64, or in user and temporary folders.
- ParentImage: svchost.exe not started by services.exe, or lsass.exe with any parent other than wininit.exe.
- OriginalFileName and Hashes that do not match the real Windows binary.

Often benign when:
- Rarely for core system names; some software ships helper processes with similar names in its own folder.""",
    },
]


def main() -> int:
    catalogue = json.loads((ROOT / "knowledge/attack/techniques.json").read_text(encoding="utf-8"))
    techniques = {item["attack_id"]: item for item in catalogue["techniques"] if item["kind"] == "technique"}
    tactic_names = {
        item["name"]
        for item in yaml.safe_load(
            (ROOT / "knowledge/attack/tactics_abbrev.yaml").read_text(encoding="utf-8")
        )["tactics"]
    }

    dictionary_sources: dict[tuple[str, int], str] = {}
    for path in sorted((ROOT / "knowledge/eventids").glob("*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            dictionary_sources[(entry["channel"], int(entry["event_id"]))] = entry["sources"][0]

    out_dir = ROOT / "knowledge/guidance"
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("G-*.md"):
        stale.unlink()

    problems: list[str] = []
    for note in NOTES:
        sources: list[str] = []
        for reference in note["events"]:  # type: ignore[union-attr]
            channel, _, event_id = str(reference).rpartition(":")
            url = dictionary_sources.get((channel, int(event_id)))
            if url and url not in sources:
                sources.append(url)
        for technique_id in note["techniques"]:  # type: ignore[union-attr]
            entry = techniques.get(str(technique_id))
            if entry is None:
                problems.append(f"{note['id']}: {technique_id} is not in the ATT&CK catalogue")
            elif not entry["retired"] and entry["url"] and entry["url"] not in sources:
                sources.append(entry["url"])
        for tactic in note["tactics"]:  # type: ignore[union-attr]
            if tactic not in tactic_names:
                problems.append(f"{note['id']}: unknown tactic {tactic!r}")
        if not sources:
            problems.append(f"{note['id']}: no verifiable source could be derived")

        header = {
            "id": note["id"],
            "title": note["title"],
            "applies_to": {
                "events": note["events"],
                "techniques": note["techniques"],
                "tactics": note["tactics"],
            },
            "sources": sources,
        }
        text = "---\n" + yaml.safe_dump(header, sort_keys=False, allow_unicode=True, width=200) + "---\n\n"
        text += str(note["body"]).strip() + "\n"
        (out_dir / f"{note['id']}-{note['slug']}.md").write_text(text, encoding="utf-8", newline="\n")

    for problem in problems:
        print("PROBLEM:", problem, file=sys.stderr)
    print(f"wrote {len(NOTES)} notes to {out_dir}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
