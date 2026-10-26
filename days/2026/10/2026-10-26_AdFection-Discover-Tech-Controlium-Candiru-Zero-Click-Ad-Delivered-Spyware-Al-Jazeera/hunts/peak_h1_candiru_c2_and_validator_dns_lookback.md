# PEAK hunt H1 - long-window DNS lookback for Candiru C2, validator and Bindecy-linked domains

## Prepare

**Hypothesis.** Between 2024 and 2025 at least 45 Al Jazeera Windows devices were infected through Discover-Tech ads, and Citizen Lab fingerprinted hundreds of Candiru validator domains and IPs. If any user in our estate saw one of those ads, the resolver, proxy or EDR network log holds a lookup of a validator domain, and for a successful infection a later lookup of a C2 domain.

**Why first.** It needs no sample and no exploit knowledge, and the indicators are named in a public report. The weak point is retention: the intrusions are old, so the hunt is only as good as the DNS and proxy history you kept.

**Scope.** Journalists, executives, government liaison staff, security and legal teams, and anyone who handles sensitive sources. Start with the highest-risk users, then widen to the whole estate.

**Data quality check first.** Find the oldest day of DNS, proxy and EDR network telemetry you can query and write it in the hunt notes. If retention is under 12 months, say so in the result: a clean answer then only covers that window.

## Execute

```kql
// Author: Jarmi
// Defender XDR: Candiru C2, validator and Bindecy-linked domains over the longest retained window.
let c2 = dynamic(["fearevolve.com","jobmarcher.com","insightenterprisells.com","plasticbells.com"]);
let validator = dynamic(["keyadapter.com","sharethere.net","outdooutcome.com","suggestutterly.com","sincereaccertain.com"]);
DeviceNetworkEvents
| where Timestamp > ago(730d)
| where RemoteUrl has_any (c2) or RemoteUrl has_any (validator)
| summarize First=min(Timestamp), Last=max(Timestamp), Hits=count() by DeviceName, RemoteUrl
| order by First asc
```

```bash
# Author: Jarmi
# Passive DNS or resolver logs exported as text: look for the report domains over the full archive.
zgrep -hiE '(fearevolve|jobmarcher|insightenterprisells|plasticbells)\.com|keyadapter\.com|sharethere\.net|outdooutcome\.com|suggestutterly\.com|sincereaccertain\.com' /var/log/dns/*.log* | sort | uniq -c | sort -rn | head -50
```

## Act on

- Any C2 domain hit: treat the device as compromised. Image it before any cleanup, rotate the user's credentials, and pull the user's browsing history for the hour before the first hit to find the ad-carrying site or app.
- A validator hit without a C2 hit: the device was probed. Review browser and OS patch level at the time and keep the device under watch.
- No hits: record the retention window and close with the caveat that the domains are 2024-2025 indicators.

## Knowledge

Record which log source had the longest history, whether the Citizen Lab appendix (303 further domains, 319 IPs) was loaded into a lookup, and which users sit in the highest-risk group.
