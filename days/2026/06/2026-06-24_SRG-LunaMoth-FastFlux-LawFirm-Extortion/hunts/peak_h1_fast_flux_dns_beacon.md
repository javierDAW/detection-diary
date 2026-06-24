# PEAK Hunt H1 — Fast Flux DNS Behavior in the Environment

## Hypothesis

Hosts in the environment have sent DNS queries to domains exhibiting fast flux behavior —
characterised by TTL <= 60 seconds and 5+ unique A records per domain within a 24-hour window.
At least one of those domains is attributable to SRG / Luna Moth infrastructure or to another
criminal operator using the same evasion technique.

## Prepare

**Relevant telemetry**: DNS resolver logs (Windows DNS Server analytic log, Sysmon EID 22,
proxy DNS logs, firewall DNS inspection). CISA AA25-093a defines the canonical fast flux fingerprint.

**Known-bad anchors**: `ep6pheij[.]com`, `business-data-leaks[.]com`.

**Scope**: All internal hosts, 30-day lookback.

## Execute

**Step 1 — Known IOC query (Defender XDR)**:
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("ep6pheij", "business-data-leaks")
| summarize HitCount=count(), Devices=make_set(DeviceName), FirstSeen=min(Timestamp)
    by RemoteUrl, RemoteIP
| order by HitCount desc
```

**Step 2 — Low TTL anomaly hunt (DNS Server logs via Sysmon EID 22)**:
```kql
// Sysmon EID 22 does not capture TTL; enrichment via external pDNS query is required.
// Use Farsight DNSDB / SecurityTrails / CIRCL pDNS to check A-record history for domains
// that appear frequently in your DNS query logs but are not on your internal allow-list.

// Example: find top external domains queried > 50 times/hour by any single host (unusual cadence)
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where RemoteUrl !endswith ".microsoft.com" and RemoteUrl !endswith ".windows.com"
    and RemoteUrl !endswith ".office.com" and RemoteUrl !endswith ".google.com"
| summarize QueryCount=count(), UniqueIPs=dcount(RemoteIP)
    by DeviceName, RemoteUrl, bin(Timestamp, 1h)
| where QueryCount > 50 and UniqueIPs > 3
| order by UniqueIPs desc
```

## Analyze

- Any match on the known IOC query (Step 1) is a confirmed SRG indicator — escalate immediately.
- High QueryCount + high UniqueIPs for the same domain within 1 hour is a fast flux behavioral signal.
- Correlate querying hosts with RMM software installation events (see H2) and bulk outbound transfer (see H3).

## Report

- If known IOC hit: Escalate to IR. Collect DNS cache, process list, network connections on the affected host.
- If behavioral anomaly only: Cross-check domain with pDNS to confirm TTL <= 60s and IP rotation across ISPs.
  Document findings, submit domain to threat intelligence feeds, and notify CISA if confirmed criminal fast flux.

## References

- [Resecurity SRG Fast Flux report](https://www.resecurity.com/blog/article/silent-ransom-group-srg-uncovering-dns-fast-flux-infrastructure)
- [CISA AA25-093a — Fast Flux: A National Security Threat](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-093a)
