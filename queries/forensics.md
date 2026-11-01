# Phase 4 – Peer-to-Peer Attack & Forensics

Reconstructing the timeline of a classmate who logged in via RDP and performed
"suspicious" actions. Each query maps one stage of the attack chain.

- **Workspace:** `sentinel-bait-n-switch`
- **Tables:** `SecurityEvent` (Windows Security log), `Event` (Sysmon)

```kql
// Fill in and paste on top of any query below.
let AttackStart = datetime(2026-10-30T16:48:00Z);   // when the classmate started (UTC!)
let AttackEnd   = datetime(2026-10-30T17:10:00Z);   // when they finished (UTC!)
let ClassmateIP = "CLASSMATE_IP";                   // their public source IP
let SessionId   = "0x9235dc";                       // TargetLogonId from the 4624 (step 1)
```

> **Times are UTC.** Local time (CET) is +1h. The session was isolated via the RDP logon's
> `TargetLogonId`, which appears in every process event of that session — more reliable than
> filtering by IP, since Sysmon process events carry no source IP.

---

## 1. Find the logon session (EventID 4624)

Get the classmate's RDP login and its `TargetLogonId`. `LogonType == 10` = RDP.

```kql
let ClassmateIP = "CLASSMATE_IP";
SecurityEvent
| where EventID == 4624
| where IpAddress == ClassmateIP
| project TimeGenerated, Account, IpAddress, LogonType, TargetLogonId
| order by TimeGenerated asc
```

## 2. Commands executed (Sysmon EventID 1)

The heart of the forensics — full command lines. Extract the CommandLine into its own
column instead of reading raw `RenderedDescription`. Filter the Windows background noise
with a **blacklist** (see note below).

```kql
let NoiseList = dynamic(["svchost", "taskhostw", "sihost", "rdpclip", "userinit",
                         "Explorer.EXE", "ShellHost", "StartMenuExperience",
                         "SecurityHealth", "smartscreen", "rundll32", "ServerManager",
                         "TSTheme", "DefenderSessionHelper", "fclip", "devicecensus",
                         "OpenConsole", "wt.exe", "WindowsTerminal", "MoUsoCoreWorker"]);
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| extend CommandLine = extract(@"CommandLine: (.*?) CurrentDirectory", 1, RenderedDescription)
| extend User = extract(@"User: (.*?) LogonGuid", 1, RenderedDescription)
| where User has "azureuser"
| where not(CommandLine has_any (NoiseList))
| project TimeGenerated, CommandLine
| order by TimeGenerated asc
```

> **Whitelist vs. blacklist — a real detection lesson.** A *whitelist* (only show known
> attacker tools like `net`, `sc`, `schtasks`) is cleaner to read but **misses anything not
> on the list** — e.g. a `certutil` download. A *blacklist* (hide known-good noise) keeps
> unexpected activity visible. For the report screenshot a whitelist is fine; for real
> hunting, prefer the blacklist. *You only find what you ask for.*

## 3. New local user (EventID 4720)

```kql
SecurityEvent
| where EventID == 4720
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| project TimeGenerated, Activity, TargetAccount, SubjectAccount
| order by TimeGenerated asc
```

## 4. User added to a privileged group (EventID 4732)

```kql
SecurityEvent
| where EventID == 4732
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| project TimeGenerated, Activity, TargetUserName, MemberName, SubjectAccount
| order by TimeGenerated asc
```

## 5. Firewall disabled

```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| where RenderedDescription has_any ("netsh advfirewall", "Set-NetFirewallProfile")
| extend CommandLine = extract(@"CommandLine: (.*?) CurrentDirectory", 1, RenderedDescription)
| project TimeGenerated, CommandLine
| order by TimeGenerated asc
```

## 6. Scheduled task created (EventID 4698)

```kql
SecurityEvent
| where EventID == 4698
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| project TimeGenerated, Activity, SubjectAccount
| order by TimeGenerated asc
```

## 7. Registry Run key (Sysmon EventID 13)

```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 13
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| where RenderedDescription has @"CurrentVersion\Run"
| project TimeGenerated, RenderedDescription
| order by TimeGenerated asc
```

## 8. PowerShell download — network layer (Sysmon EventID 3)

**Key finding.** The download leaves no process event (`Invoke-WebRequest` runs in-process)
and no 4104 (Script Block Logging was off). It is visible **only** as an outbound network
connection. Do **not** filter on `Image has "powershell"` — the connection may not originate
from powershell.exe and would be missed. Run the full egress list instead:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| extend Image    = extract(@"Image: (.*?) User:", 1, RenderedDescription)
| extend DestIP   = extract(@"DestinationIp: ([^\s]+)", 1, RenderedDescription)
| extend DestPort = extract(@"DestinationPort: ([0-9]+)", 1, RenderedDescription)
| extend DestHost = extract(@"DestinationHostname: (.*?) DestinationPort", 1, RenderedDescription)
| project TimeGenerated, Image, DestIP, DestPort, DestHost
| order by TimeGenerated asc
```

Look for an outbound `:443` to an external host (e.g. `185.199.109.133` / `*.github.com`).
Internal `172.16.0.4:3389` rows = NAT'd RDP session traffic; `::1:5985` = WinRM remoting.

---

## 9. Full session timeline (all sources)

Merge everything in the session window into one chronological view for the report. Captures
only what telemetry *recorded* — not necessarily everything the attacker did.

```kql
union
  (SecurityEvent
   | where EventID in (4624, 4720, 4732, 4698, 4950, 5025)
   | extend What = strcat("SecurityEvent ", tostring(EventID), " – ", Activity)),
  (Event
   | where Source == "Microsoft-Windows-Sysmon" and EventID in (1, 3, 13)
   | extend What = strcat("Sysmon ", tostring(EventID)))
| where TimeGenerated between (datetime(2026-10-30T16:48:00Z) .. datetime(2026-10-30T17:10:00Z))
| project TimeGenerated, What, RenderedDescription
| order by TimeGenerated asc
```

---

### Verification checklist (Phase 4, step 4)

| Expected action | Captured? | Via |
|---|---|---|
| RDP login | ✅ | 4624 (LogonType 10) |
| Recon (whoami, systeminfo) | ✅ | Sysmon 1 |
| New user | ✅ | 4720 + Sysmon 1 |
| Add to Administrators | ✅ | 4732 + Sysmon 1 |
| Disable firewall | ✅ | netsh via Sysmon 1 |
| Scheduled task | ✅ | 4698 + Sysmon 1 |
| Registry Run key | ✅ | Sysmon 13 |
| **PowerShell download** | ⚠️ partial | Sysmon 3 only (network) — no command, no 4104 |
| *Bonus:* service creation (not on brief) | ✅ | Sysmon 1, auto-tagged T1031/T1050 |
