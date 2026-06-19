# PEAK Hunt H1 — ATG Internet Exposure Inventory

**Case**: Iran-nexus ATG cyber-physical campaign (IC3-260602)
**Date**: 2026-06-19
**Author**: Jarmi
**Slot**: #22 OT physical / cyber-physical
**MITRE**: T1595.002, T1190, T0842 (Network Sniffing - OT)

---

## Hypothesis

Threat actor used internet scanning tools (Shodan, Censys, custom scanners) to identify
Veeder-Root ATG devices with port 10001/tcp exposed to the internet, then selected targets
with default or no credentials. Shadowserver documented 1,061 IPs with port 10001/tcp
reachable as of 2026-06-05. Our environment may have ATG units unknown to the SOC that
are internet-exposed because of misconfigured firewall rules or direct-connected modems
installed by fuel vendors.

**Goal**: enumerate all ATG systems in our estate, determine which have port 10001 reachable
from the internet, and confirm no unauthorized logins.

---

## Telemetry Sources

- Firewall / NGFW traffic logs (NetFlow, sFlow, firewall allow/deny)
- SIEM network baseline (Sentinel / Defender XDR DeviceNetworkEvents)
- Asset inventory (CMDB, OT asset management — Claroty, Nozomi, Dragos)
- Passive DNS / network discovery (Shodan Monitor alerts if subscribed)

---

## Hunt Queries

### Step 1 — Enumerate assets with port 10001/tcp (OT inventory)

```bash
# On OT management jump host — active scan of known OT CIDR blocks for port 10001
# Only run with authorization and change-management approval
nmap -p 10001 --open -oG atg_scan_$(date +%Y%m%d).txt <OT_CIDR_BLOCK>
grep "10001/open" atg_scan_$(date +%Y%m%d).txt | awk '{print $2}'
```

### Step 2 — Check firewall logs for inbound port 10001 allow rules

```kql
// Sentinel — firewall allow traffic inbound to port 10001 from non-RFC1918
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DestinationPort == 10001
| where DeviceAction !in ("deny","drop","block","Reset")
| where not(ipv4_is_private(SourceIP))
| summarize
    SessionCount = count(),
    UniqueSourceIPs = dcount(SourceIP),
    SourceIPList = make_set(SourceIP, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DestinationIP, DestinationPort, DeviceName
| order by SessionCount desc
```

### Step 3 — Validate no external IPs accessed ATG management 30 days back

```kql
// Defender XDR
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort == 10001
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

---

## Expected vs Anomalous

| Signal | Expected | Anomalous |
|--------|----------|-----------|
| Port 10001 inbound | Zero from internet; only from OT management VLAN | Any from non-RFC1918 |
| ATG in asset inventory | All units documented | Unknown ATGs found |
| Authentication events | Only from documented operator terminals | New source IPs |
| Firewall rule for 10001 | Inbound deny from internet | ANY allow from internet |

---

## Actions

1. If any ATG has port 10001 reachable from internet: **block immediately at firewall**.
2. Document all ATG IPs and add to Shadowserver Monitor watchlist.
3. Request vendor (Veeder-Root / OPW / Franklin Fueling) confirmation of firmware version
   — patch if vulnerable to CVE-2025-58428.
4. Escalate any confirmed inbound connections to DFIR.
