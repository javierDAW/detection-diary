# PEAK Hunt H2 — ATG Authentication Anomalies and Credential Abuse

**Case**: Iran-nexus ATG cyber-physical campaign (IC3-260602)
**Date**: 2026-06-19
**Author**: Jarmi
**Slot**: #22 OT physical / cyber-physical
**MITRE**: T1078, T1110.001, T1110.003, T0859 (Valid Accounts - OT)

---

## Hypothesis

The advisory documents authentication bypass and hardcoded credentials as primary access
vectors. Attackers connecting to exposed ATGs either: (a) exploit a hardcoded credential
that never requires a password prompt, (b) brute-force the 8-digit PIN default, or (c)
bypass authentication entirely via the auth bypass flaw. After gaining access, they log in
as administrator and make configuration changes that suppress leak detection alerts.

**Goal**: detect authentication events (success or failure bursts) on ATG management
interfaces from unexpected source IPs, and correlate with subsequent configuration changes.

---

## Telemetry Sources

- ATG management system logs (Veeder-Root SMS, FuelsManager, OilDoc, VR Fuel-Site Suite)
- OT platform event logs (Claroty, Nozomi, Dragos — if deployed in ATG segment)
- Network authentication events forwarded via CEF/syslog to SIEM

---

## Hunt Queries

### Step 1 — Burst authentication from new source IPs (brute-force / recon)

```kql
// Sentinel — CommonSecurityLog from OT CEF forwarder (Claroty/Nozomi)
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceProduct has_any ("Veeder-Root","ATG","TLS4","FuelsManager")
| where Activity has_any ("LOGIN_FAILED","AUTH_FAILED","LOGIN_SUCCESS","AUTH_SUCCESS")
| summarize
    TotalEvents = count(),
    FailureCount = countif(Activity has "FAILED"),
    SuccessCount = countif(Activity has "SUCCESS"),
    SourceIPs = make_set(SourceIP, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, DestinationIP, bin(TimeGenerated, 1h)
| where FailureCount > 5 or (FailureCount > 2 and SuccessCount > 0)
| extend BruteForceIndicator = iff(FailureCount > 2 and SuccessCount > 0, "CREDSTUFFING", "BRUTEFORCE")
| order by TotalEvents desc
```

### Step 2 — New administrator login from unknown IP after hours

```kql
// Sentinel — Syslog from ATG Linux OS (if syslog forwarder deployed)
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has_any ("Accepted password","Accepted publickey","session opened for user root","su: session opened")
| where Computer has_any ("<add_known_atg_hostnames>") or Computer startswith "atg-"
| extend LoginHour = hourofday(TimeGenerated)
| where LoginHour !between (7 .. 18)  // flag after-hours logins
    or SyslogMessage has "root"        // always flag root logins
| project TimeGenerated, Computer, SyslogMessage, HostIP
| order by TimeGenerated desc
```

### Step 3 — Configuration change immediately following login (pivot to T0836/T0831)

```kql
// Correlate login events with subsequent config change events within 5 minutes
let logins = CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceProduct has_any ("Veeder-Root","ATG","TLS4")
    | where Activity has "LOGIN_SUCCESS"
    | project LoginTime = TimeGenerated, DeviceName, SourceIP;
let configchanges = CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceProduct has_any ("Veeder-Root","ATG","TLS4")
    | where Activity has_any ("CONFIG_CHANGE","ALARM_DISABLED","SETPOINT_MODIFIED","THRESHOLD_CHANGED")
    | project ChangeTime = TimeGenerated, DeviceName, ChangeActivity = Activity;
logins
| join kind=inner configchanges on DeviceName
| where ChangeTime between (LoginTime .. (LoginTime + 5m))
| project LoginTime, ChangeTime, DeviceName, SourceIP, ChangeActivity
| order by LoginTime desc
```

---

## Expected vs Anomalous

| Signal | Expected | Anomalous |
|--------|----------|-----------|
| Auth source IPs | Documented operator terminals only | New IPs, especially external |
| Failed login count | 0-2 per hour (fat-finger) | >5 per hour burst |
| After-hours logins | Rare, with change ticket | Undocumented root login |
| Config change post-login | With change window notification | Immediate, no notice |
| Alarm status | All active | Any alarm disabled without documented maintenance |

---

## Actions

1. Any confirmed unauthorized login: isolate the ATG from network immediately.
2. Inventory and rotate all ATG credentials (factory default passwords documented per vendor manuals).
3. Review alarm status on all ATGs for suppressed leak detection.
4. Escalate to physical safety team if any leak detection alarm was disabled.
