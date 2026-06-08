# PEAK Hunt H1 — IIS worker hex-subdomain DNS self-report beacon

**Hypothesis.** If an OP-512-style web shell is deployed on an IIS host, then the worker process `w3wp.exe` will emit outbound DNS queries carrying abnormally long, hex-segmented subdomain labels (the shell encoding its own URL to report deployment location), which is atypical for a web server.

**ATT&CK.** T1071.004 (DNS), T1071.001 (Web Protocols), T1132.001 (Standard Encoding).

## Prepare

- Telemetry: Sysmon EID 22 (DNS query) with process attribution, or Defender `DeviceNetworkEvents`, or resolver/edge DNS logs that can be correlated to source host + process.
- Scope: internet-facing / DMZ IIS hosts first. Baseline normal DNS from web-server hosts — some CDN/analytics services emit long subdomains.

## Execute

```kql
DeviceNetworkEvents
| where Timestamp > ago(45d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| extend Host = tolower(coalesce(RemoteUrl, ""))
| where Host matches regex @"\.[0-9a-f]{16,}\." or Host has_any ("hcgos.com","lhlsjcb.com")
| summarize Queries = count(), Sample = any(RemoteUrl), Apexes = make_set(Host, 20) by DeviceName, bin(Timestamp, 1h)
| order by Queries desc
```

## Analyze

- Long hex labels from `w3wp.exe` are the core tell. Confirm by decoding the hex segment — for OP-512 it resolves to the web shell's own path. A repeating beacon roughly every 5 minutes (the self-report cooldown) strengthens confidence.
- Pivot any positive host to H2 (worker spawning shells / reflective loads) and H3 (web shell + temp DLL) to confirm the full chain.

## Act

- If confirmed: isolate the host (do not just kill the process), preserve memory, and treat the shell as already alerting the operator — investigate from logs, do not browse the URL.
- Feed confirmed apexes/IPs to blocklists as *supporting* indicators only; the durable detection is the behavioral pattern, since the C2 rotates.
