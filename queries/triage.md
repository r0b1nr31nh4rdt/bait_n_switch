# Phase 3 – The Stakeout (Triage)

KQL queries for analyzing the RDP brute-force attacks against the honeypot.

- **Workspace:** `sentinel-bait-n-switch`
- **Table:** `SecurityEvent` (via AMA/DCR, *All Security Events*) and `Event` (Sysmon)
- Fill in the known non-attacker IPs below (own test IP, classmate, localhost). They are
  excluded from the attack queries so only real external attackers remain.

```kql
// Paste this let-block on top of any query below, or keep one query per block.
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
```

> **Finding (exposure window):** one dominant external IP from Belgium — 463 failed
> attempts in 139 s (**3.33/s**) against default accounts (`Administrator`, `Admin`,
> `Guest`), client-supplied workstation name `ACCUEIL-PC` → automated brute-force tool.
> A second group of IPs targeted the account `Test` (different wordlist = independent campaign).

---

## 1. Overview: failed attempts per attacker IP

`dcount(Account)` reveals whether an IP cycles through multiple accounts.
`make_set(Account)` lists the actual usernames tried.

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count(),
            Accounts = dcount(Account),
            TriedAccounts = make_set(Account),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by IpAddress
| order by Attempts desc
```

## 2. Most-targeted usernames (Top 20)

Shows which usernames are most popular — and `SourceIPs` reveals whether a username is
hit by many IPs (common target) or just one (single campaign).

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count(), SourceIPs = dcount(IpAddress) by Account
| order by Attempts desc
| take 20
```

## 3. Attack rate: duration and attempts per second

Hard metric for "automated vs. human". **Finding: 463 attempts / 139 s = 3.33/s.**

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count(),
            StartTime = min(TimeGenerated),
            EndTime = max(TimeGenerated)
| extend DurationSeconds = datetime_diff('second', EndTime, StartTime)
| extend AttemptsPerSecond = round(todouble(Attempts) / DurationSeconds, 2)
```

## 4. Timeline (use bar chart, not line)

A single point = all attempts in one bucket. Render as a **bar/column** chart — a line
chart interpolates between sparse points and fakes a trend that isn't there.

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count() by bin(TimeGenerated, 10m)
| render columnchart
```

## 5. Protocol / LogonType / workstation name

`NTLM` = non-domain logon to a local account (standalone host) — says **nothing** about
the attacker's OS. `WorkstationName` is a client-supplied (spoofable) string.

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count() by LogonType, AuthenticationPackageName, WorkstationName
| order by Attempts desc
```

## 6. Geo-IP: attacker IP → country / city

> **Note:** `geo_info_from_ip_address()` runs reliably in the **Sentinel Logs view**
> (Azure portal). In Defender Advanced Hunting the function may be missing/fail.

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (KnownIPs)
| summarize Attempts = count() by IpAddress
| extend geo = geo_info_from_ip_address(IpAddress)
| project IpAddress,
          Country = tostring(geo.country),
          City = tostring(geo.city),
          Attempts
| order by Attempts desc
```

## 7. RDP port connections (Sysmon Event 3) — the "silent" probers

**Key insight:** the Security log (4625) only sees IPs that *submit credentials*. IPs that
merely connect to the RDP port never appear there. Sysmon Event 3 exposes them — including
one IP that probed for ~19 hours without a single credential attempt, invisible in 4625.

> Note: internal RDP traffic shows as the NAT'd internal IP `172.16.0.4:3389`, not the
> public source — Azure translates the address before Sysmon sees it. The real public
> source IP is only in the Logon events (4624/4625).

```kql
let KnownIPs = dynamic(["YOUR_TEST_IP", "CLASSMATE_IP", "::1"]);
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| where RenderedDescription has "3389" or RenderedDescription has "RDP"
| extend SourceIP = extract(@"SourceIp: ([0-9\.]+)", 1, RenderedDescription)
| where SourceIP != "" and not(SourceIP startswith "172.16") and SourceIP !in (KnownIPs)
| summarize Connections = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by SourceIP
| order by Connections desc
```
