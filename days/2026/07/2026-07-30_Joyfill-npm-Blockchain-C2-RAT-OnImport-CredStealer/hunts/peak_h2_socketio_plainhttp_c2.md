# PEAK Hunt H2 — Plain-HTTP Socket.IO channel to an unfamiliar IP from a dev/CI host

**Hypothesis.** The Joyfill implant's stage-3 RAT opened a Socket.IO channel to its campaign C2 over **plain HTTP on port 443** (SOCKET_URL `http://166.88.134.62:443`), and staged file exfiltration to `/u/f`. A cleartext HTTP service on 443, or `/socket.io/` traffic to a non-allowlisted IP, is the first unmistakable indicator.

**Prepare (data).** Network telemetry (Zeek/Suricata `http`, Defender `DeviceNetworkEvents`), plus proxy/egress logs. HTTP-on-443 detection needs L7 visibility, not just port heuristics.

**Execute (analytic).**
```kql
let c2ips = dynamic(["166.88.134.62","23.27.13.43","198.105.127.210","23.27.202.27"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (c2ips)
    or (RemoteUrl has "/socket.io/" and RemotePort == 443 and Protocol == "Http")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp asc
```

**Act.** Any hit on the C2 IPs is high-confidence — isolate the host, capture the `node` process memory if still live (payload stages exist only in memory), and begin credential rotation. For `/socket.io/`-over-plain-HTTP-443 hits to unknown IPs, validate the destination against your allowlist before escalating.

**Notes / pitfalls.** Indicators decay — the C2 may already be sinkholed or reassigned (StepSecurity observed no live callout post-disclosure). Absence of a callout does NOT clear a host that imported a `2773` build; the loader may simply have found no server. Pivot to file-integrity evidence (H3).

**Refine.** Add confirmed C2 IPs to block lists with an expiry/review date; alert on any cleartext HTTP observed on port 443 egress as a durable, campaign-agnostic signal.
