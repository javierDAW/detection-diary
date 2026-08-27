# PEAK hunt H1 - Retrospective hunt for QTFY infrastructure contact (DNS, proxy, flow)

## Prepare

**Hypothesis.** If our estate was ever scanned, exploited or used as a relay by QTFY, then somewhere in DNS, proxy, firewall or EDR
network telemetry there is a record of a host resolving or contacting one of the domains or addresses the FBI, NSA and Cyber National
Mission Force published on 2026-08-26. The DoJ seized the core domains the same day, so any evidence is historical by definition:
this hunt is a look back, not a live detection.

**Why this first.** It is the cheapest hunt in the pack, it needs only data most teams already retain, and its result decides how
much effort the other two deserve. The advisory describes activity from May 2018 to June 2026, so the useful lookback is as long as
your retention allows, not 30 days.

**Scope.** All DNS resolver logs, secure web gateway and proxy logs, perimeter firewall logs and EDR network events. Include
branch-office routers and any device that forwards logs, because QTRouter traffic is designed to originate from small devices.

**Read the dates correctly.** In the advisory CSV a `last_seen` in the future is a registration expiry date, not an activity date,
and a few rows show `last_seen` earlier than `first_seen`. Use the dates to decide which indicator families to prioritise, never to
exclude a hit.

**Data quality check first.** Confirm you can query DNS for at least 12 months. If retention is shorter, record the gap as a
finding and still run the hunt over what exists.

## Execute

```kql
// Domain half. Defender XDR advanced hunting; adapt table names for your DNS source.
let qtfy = dynamic(["qt-proxy.org","qt-team.com","qtproxy.xyz","qtcyber.com","instantmessagehub.tech","fastsecurey.info",
                    "anticonstitutionally.sbs","oraclelabs.biz","wintel.biz","worldswar.online","onlion.shop","ccgv.me","categorystore.net"]);
union
  (DeviceNetworkEvents | where Timestamp > ago(365d) | where RemoteUrl has_any (qtfy) | project Timestamp, DeviceName, Source="network", Target=RemoteUrl, Proc=InitiatingProcessFolderPath),
  (DeviceEvents | where Timestamp > ago(365d) and ActionType == "DnsQueryResponse"
   | extend Q = tostring(parse_json(AdditionalFields).DnsQueryString) | where Q has_any (qtfy)
   | project Timestamp, DeviceName, Source="dns", Target=Q, Proc=InitiatingProcessFolderPath)
| summarize First=min(Timestamp), Last=max(Timestamp), Hits=count() by DeviceName, Target, Source
| sort by First asc
```

```bash
# Author: Jarmi
# Resolver or proxy text logs: count hits per client for the core QTFY domains.
zgrep -hiE '(qt-proxy\.org|qt-team\.com|qtproxy\.xyz|qtcyber\.com|instantmessagehub\.tech)' /var/log/named/*.log* /var/log/squid/access.log* 2>/dev/null \
  | awk '{print $1, $2, $3, $0}' | cut -c1-200 | sort | uniq -c | sort -rn | head -50
```

```kql
// Address half. Firewall or flow logs in Sentinel; the list is the actor-controlled and QScan server set from iocs.csv.
let qtfy_ips = dynamic(["154.64.238.222","154.64.238.247","1.32.216.171","23.95.220.192","39.104.208.77","45.202.210.27","206.119.167.207","103.201.131.121"]);
CommonSecurityLog
| where TimeGenerated > ago(365d)
| where DestinationIP in (qtfy_ips) or SourceIP in (qtfy_ips)
| summarize First=min(TimeGenerated), Last=max(TimeGenerated), Bytes=sum(SentBytes + ReceivedBytes) by SourceIP, DestinationIP, DestinationPort
| sort by First asc
```

## Act

**A host that resolved a core QTFY domain (qt-proxy.org, qt-team.com, qtproxy.xyz) before 2026-08-26** is an open lead. Pull the
initiating process, the surrounding 24 hours of process and network telemetry, and check whether the host is an edge device, a
router or a server running a service from the advisory CVE list. Resolution of a domain by a SOHO router or an internet-facing
appliance is more serious than by a researcher workstation.

**Inbound hits from the QScan worker or server addresses** mean the estate was scanned. Scanning alone is not compromise; pair it
with H2 to find out whether the scanned service was vulnerable.

**Nothing found** is a limited result: record the retention window and which log sources were covered, because ORB traffic from
nearby compromised devices does not touch the published infrastructure at all. Move to H3.

## Knowledge

Record the retention depth per log source and the earliest date covered. Feed any confirmed host back into the IOC feed as a
local sighting with its first and last time. Note which indicator families produced hits so the next advisory refresh can be
prioritised the same way.
