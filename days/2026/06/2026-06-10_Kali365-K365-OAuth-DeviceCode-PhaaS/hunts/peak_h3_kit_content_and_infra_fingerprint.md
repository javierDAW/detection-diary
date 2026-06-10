# PEAK Hunt H3 — kit content and infrastructure fingerprint

**Hypothesis.** If a user in our environment loaded a Kali365 lure, then web/proxy and endpoint telemetry will show either a connection to the operator's rotating Worker/cPanel infrastructure or the kit's stable content fingerprint — the "Preparing your secure document..." loader and the C2 poll to `panel.securehubcloud.com` every three seconds. Because subdomains rotate within days, the content and certificate fingerprints outlive any single domain.

**ATT&CK.** T1071.001 (Application Layer Protocol: Web Protocols), T1566.002 (Spearphishing Link), T1656 (Impersonation).

## Prepare

- Telemetry: `DeviceNetworkEvents` / secure web gateway / proxy logs, and passive DNS or CTI host-response telemetry (VALIDIN-style) for the certificate and banner pivots.
- Durable fingerprints: TLS cert SHA1 `6894a51278ec89118276c2dd2dc36e6f9ea2790a`, HTTP banner hash `febb622cd9eeb5c8860dcef4cbfd4b74`, page title `K365 Control`, content `Preparing your secure document`.

## Execute

```kql
let kitDomains = dynamic(["securehubcloud.com","attachedfile.com","greatness-marketing.top","mowell.tech"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| extend host = tolower(RemoteUrl)
| where isnotempty(host)
| where host endswith "securehubcloud.com" or host endswith "attachedfile.com"
    or host endswith "greatness-marketing.top" or host endswith "mowell.tech"
    or host endswith ".workers.dev"
| summarize Hits = count(), Hosts = make_set(host, 20), Procs = make_set(InitiatingProcessFileName, 5),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessAccountName
| sort by LastSeen desc
```

## Analyze

- Any connection to `panel.securehubcloud.com` is, by Arctic Wolf's assessment, a workstation that rendered a live Kali365 page — treat as confirmed. `attachedfile.com` (39 subdomains) has no legitimate use.
- `.workers.dev` is broad and benign at large; use it only to surface candidates, then confirm with the content string in proxy response bodies (`content:"Preparing your secure document..."`) or a VirusTotal/URLScan retro-hunt on the same string.
- For the C2/cert/banner pivots, run them in passive-DNS / CTI tooling rather than only on local logs, to enumerate sibling infrastructure before it rotates.

## Act

- Block `panel.securehubcloud.com` and `*.attachedfile.com` at egress; submit the content and certificate fingerprints to the web gateway and EDR custom IOCs.
- For any device with a hit, pivot to H1/H2 on the signed-in user to determine whether tokens were issued and used. Treat a content-fingerprint hit plus a device-code sign-in by the same user as a confirmed compromise.
