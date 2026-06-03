# PEAK Hunt H3 — image-only email links to reverse-DNS strings

**Hypothesis:** Inbound email delivered links to `ip6.arpa` reverse-DNS hosts,
hidden inside images, that bypassed domain-reputation scoring at the gateway.

## Prepare

The lure hides the URL inside an `<img>`/`<a>` so the recipient sees a graphic
(prize/survey/account/brand spoof) and never a strange `…ip6.arpa` host. Because
`.arpa` carries no WHOIS, domain age, or registrar contact, reputation engines
have nothing to score and pass the link. The hunt looks for delivered/clicked
URLs with an `ip6.arpa` host and for image-only clickable messages as a heuristic.

- Data sources: Defender `EmailUrlInfo`, `UrlClickEvents`, `EmailEvents`; or any
  gateway that extracts hyperlinks from message markup.
- Scope: all inbound mail, 90-day look-back.

## Execute

```kql
let mail =
    EmailUrlInfo
    | where Timestamp > ago(90d)
    | where Url has ".ip6.arpa"
    | project Timestamp, NetworkMessageId, Url, UrlDomain;
let clicks =
    UrlClickEvents
    | where Timestamp > ago(90d)
    | where Url has ".ip6.arpa"
    | project ClickTime = Timestamp, NetworkMessageId, AccountUpn, Url, ActionType, IPAddress;
mail
| join kind=leftouter clicks on NetworkMessageId
| project Timestamp, ClickTime, AccountUpn, Url, UrlDomain, ActionType, IPAddress
| order by Timestamp desc
```

Regex fallback for raw gateway logs:
`[a-z0-9]{4,}(\.[0-9a-f]){6,}\.ip6\.arpa`

## Act

Quarantine and pull matching messages; recover the `.eml`, extract the reverse-DNS
host and resolved IP for IOC enrichment. For clicked recipients, force credential
reset and revoke sessions, then check IdP sign-in logs for impossible-travel or
new-IP authentication consistent with downstream AiTM/credential reuse.
