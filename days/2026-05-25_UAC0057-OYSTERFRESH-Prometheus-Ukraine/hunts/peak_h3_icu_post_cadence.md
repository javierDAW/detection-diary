# PEAK H3 — Sustained ~10-minute HTTP POST cadence to a .icu FQDN from a single host

## Hypothesis
At least one host in our estate has, in the last 30 days, exhibited a sustained HTTP POST cadence to a `.icu` FQDN with intervals close to 600 seconds (±60s) across three or more successive intervals. This is the C2 heartbeat anchor that CERT-UA documents for OYSTERBLUES (advisory #6315762, 22-May-2026) — the implant ships the host profile every ~10 minutes to its Cloudflare-fronted `.icu` C2 so the operator has a steady stream on which to decide go / no-go for the Cobalt Strike payload.

## Why this discriminates
A ~10-minute fixed cadence is a strong behavioural anchor. Legitimate `.icu` traffic exists but is dominated by interactive browsing patterns (bursty, irregular) or static-asset fetches (one-off). A fixed-interval POST cadence to the same FQDN is the textbook beaconing pattern; combined with the `.icu` TLD (statistically rare in legitimate enterprise outbound), it is high-fidelity. The discriminator survives FQDN rotation: the cadence holds even if the operator rotates the C2 host weekly.

## Expected benign vs malicious
- Benign: a SaaS health-check ping to a `.icu` URL (rare, almost always business-known); identifiable by source process (browser, dedicated agent) and signer.
- Benign: a synthetic-monitoring tool egressing through a corporate proxy; identifiable by source IP being the proxy and not an endpoint.
- Malicious: a managed endpoint (laptop, desktop, server) initiating a fixed-cadence POST to a `.icu` host with source process `wscript.exe` (or a child masqueraded as `MicrosoftEdgeUpdate.exe`); high-confidence OYSTERBLUES beacon.

## Data sources
- Defender XDR — `DeviceNetworkEvents` (HTTP + DNS).
- Sysmon EID 22 (DNS) — `QueryName` ending in `.icu`.
- Sysmon EID 3 (network connect) — `Image` + `DestinationIp` + `DestinationPort`.
- Network IDS / NSM — Zeek `http.log` + `dns.log` (UID + originator + responder).
- Cloud-egress logs (Zscaler, Netskope, Cloudflare Zero Trust) — flow records with URL.

## Search logic
```kql
// Defender XDR — sustained .icu POST cadence per host
let lookback = 30d;
let window = 12h;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "HttpConnectionInspected")
| where RemoteUrl endswith ".icu" or RemoteUrl matches regex @"\.icu(\:|/)"
| summarize hits = count(),
            timestamps = make_list(Timestamp),
            fqdns = make_set(RemoteUrl)
          by DeviceName, bin(Timestamp, window)
| where hits >= 3
| mv-expand t = timestamps
| order by DeviceName asc, t asc
| serialize
| extend delta_sec = datetime_diff('second', todatetime(t), prev(todatetime(t)))
| where delta_sec between (540 .. 660)   // ~10-minute beat ±60s
| summarize beats = count() by DeviceName, fqdns
| where beats >= 3
```

For Zeek, group `http.log` by `id.orig_h` and `host`, compute consecutive timestamp deltas, keep groups with at least three deltas in `[540, 660]` seconds.

## Time window
30 days. Extend to 90 days if the initial query returns nothing — operators sometimes rotate to longer beats (15 or 20 min) to evade fixed-window hunts.

## Action on match
1. Isolate the host. Snapshot RAM. Run the IR playbook from `README.md`.
2. Pull the source process from the same Defender XDR query (extend `project` with `InitiatingProcessFileName`); confirm `wscript.exe` or an Edge-Update masquerade.
3. Quarantine the `.icu` FQDN at DNS sinkhole + IDS.
4. Sweep the entire estate for outbound to the same FQDN — UAC-0057 sends the lure to many recipients and the C2 reuse across victims is the norm.
5. Search the email gateway for the originating message; quarantine the partner mailbox if it is compromised.

## Notes
- The cadence is configurable on the operator side; the documented ~10-minute value is the CERT-UA observation as of May 2026. If the cadence shifts, broaden the delta window or drop the cadence filter and rely on the FQDN-set discriminator alone.
- Pair with H1 (wscript+js+archive path) and H2 (Edge-Update masquerade) for a three-anchor coverage of the full chain.
