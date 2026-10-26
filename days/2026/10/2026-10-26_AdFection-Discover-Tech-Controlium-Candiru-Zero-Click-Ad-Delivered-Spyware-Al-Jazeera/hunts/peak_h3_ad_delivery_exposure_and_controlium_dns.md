# PEAK hunt H3 - exposure to the Discover-Tech Controlium ad infrastructure

## Prepare

**Hypothesis.** Between March and June 2026 Discover-Tech bids placed attacker script tags in ads shown in 75,373 mobile apps and 120,768 websites, and Confiant saw impressions on government and defence networks. If our users or networks resolved Controlium hosts, they were exposed to the delivery channel, whether or not they were targeted.

**Why third.** It measures exposure and drives mitigation (ad blocking, DNS filtering), rather than detecting an infection. Most hits will be benign ad rendering, so the output is a prioritised user list, not a list of compromised hosts.

**Scope.** Resolver and proxy logs for the whole estate, then a per-user view for the high-risk group.

**Data quality check first.** Confirm that guest Wi-Fi, VPN and mobile-device traffic reach the resolver you are querying; a corporate resolver sees none of the traffic of a phone on cellular.

## Execute

```kql
// Author: Jarmi
// Defender XDR: devices that resolved Controlium or Discover-Tech hosts, ranked by volume.
let controlium = dynamic(["mtrtb.com","powerium.net","controlium.net","myweb3id.io","platc-tester.com","tracookiepixel.xyz","cookie-sync.xyz","discover-tech.io","adtimizer.co","cookiesurfer.com","volasim.com"]);
DeviceNetworkEvents
| where Timestamp > ago(120d)
| where RemoteUrl has_any (controlium)
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hosts=make_set(RemoteUrl, 10) by DeviceName, InitiatingProcessFileName
| order by Hits desc
```

```bash
# Author: Jarmi
# Resolver log view: clients that asked for the NOAS getAd hosts.
zgrep -hiE '(noas|infinoas|pqv2|events)\.(mtrtb\.com|powerium\.net|myweb3id\.io)' /var/log/dns/*.log* | awk '{print $1, $NF}' | sort | uniq -c | sort -rn | head -30
```

## Act on

- High-risk users with hits: run H1 and H2 on their devices first, and move them to a protective DNS policy that blocks the Controlium domains and, if policy allows, an ad blocker (the mitigation Citizen Lab's Marczak gives for people who may be targeted).
- Broad exposure with no sensitive users: block the domains at the resolver, record the count, and re-check after the vendor delisting takes effect.

## Knowledge

Record which user groups are exposed, which network paths bypass the corporate resolver, and the date the block went in.
