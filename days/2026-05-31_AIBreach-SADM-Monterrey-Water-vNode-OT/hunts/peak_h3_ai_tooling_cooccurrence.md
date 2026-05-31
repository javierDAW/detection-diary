# H3 — AI-accelerated tooling co-occurrence on a single host

## Frame

Prepare-Execute-Act-Know hunt. The distinguishing feature of this intrusion was
not technique novelty but *compression*: an AI-written 49-module framework ran
cloud-metadata extraction, AD interrogation, privilege escalation, and lateral
movement, iterating in hours. On a compromised host that telescopes into a tight
time window of normally-separate discovery and credential primitives.

## Hypothesis

If AI-accelerated tooling executed, a single host shows co-occurrence — within a
compressed window — of link-local cloud-metadata access, multiple distinct
AD-interrogation LOLBINs, and outbound SOCKS/reverse-proxy tunnels.

## Expected benign baseline

Admins occasionally run one or two of these. The malicious signal is the
*combination* on one host in a short window: metadata access + AD-interrogation
burst + tunnel, which legitimate workflows rarely co-locate.

## Action on match

Preserve the host (capture the large single-file Python framework before
remediation), map the tunnels' destinations, and check whether the host reached
the OT gateway (H1) or sprayed it (H2).

## Query — Defender XDR (co-occurrence join)

```kql
let window = 1h;
let meta =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any ("169.254.169.254", "latest/meta-data", "metadata/instance")
    | project DeviceName, MetaTime = Timestamp;
let adint =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("nltest.exe", "dsquery.exe", "setspn.exe", "net.exe", "net1.exe")
    | where ProcessCommandLine has_any ("/dclist", "Domain Admins", "-q */", "/domain_trusts")
    | project DeviceName, AdTime = Timestamp;
meta
| join kind=inner adint on DeviceName
| where abs(datetime_diff('minute', MetaTime, AdTime)) <= 60
| summarize Hits = count(), FirstSeen = min(MetaTime), LastSeen = max(AdTime) by DeviceName
| order by Hits desc
```

## Notes

Add the tunnel signal (Sigma 02 hits) as a third join leg where your schema
allows. The framework banner string ("BACKUPOSINT" / "APEX PREDATOR") is a bonus
host-side YARA hit but will rotate; the behavioral co-occurrence is durable.
