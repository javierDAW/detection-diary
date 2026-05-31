# H3 — egress to AMOS OpenClaw delivery and C2 infrastructure

## Frame

Prepare-Execute-Act-Know hunt. The OpenClaw AMOS campaign uses a small, fixed
set of network indicators: the fake-driver lure host
`openclawcli[.]vercel[.]app`, the first-stage loader host `91.92.242[.]30`, and
the C&C report endpoint `socifiapp[.]com/api/reports/upload`. Any egress to
these from a fleet host is high-fidelity.

## Hypothesis

If a Mac in our fleet was involved in the OpenClaw AMOS chain, we will see DNS,
TLS-SNI, or HTTP traffic to `openclawcli.vercel.app`, `socifiapp.com`, or
`91.92.242.30`, or an HTTP POST to `/api/reports/upload`.

## Expected benign baseline

None of these indicators have a legitimate business use; the only tuning needed
is to refresh the IP/loader-host set as the MaaS rotates infrastructure.

## Action on match

Block the indicators at the proxy/firewall, isolate the source host, and pivot
to H1 (loader) and H2 (Keychain collection) on the same device to scope the
full chain; assume credentials and wallets are already exfiltrated if the
report-endpoint POST is observed.

## Query — Defender XDR

```kql
let amos_domains = dynamic(["openclawcli.vercel.app", "socifiapp.com"]);
let amos_ips = dynamic(["91.92.242.30"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (amos_domains)
     or RemoteIP in (amos_ips)
     or RemoteUrl has "/api/reports/upload"
| summarize Events = count(), First = min(Timestamp), Last = max(Timestamp),
            Urls = make_set(RemoteUrl, 10)
    by DeviceName, InitiatingProcessFileName, RemoteIP
| order by Events desc
```

## Notes

Pair this with a passive-DNS / proxy-log sweep for the same indicators to catch
hosts that are not onboarded to EDR.
