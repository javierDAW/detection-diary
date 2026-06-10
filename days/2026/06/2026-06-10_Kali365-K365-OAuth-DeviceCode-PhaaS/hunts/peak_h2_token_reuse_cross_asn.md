# PEAK Hunt H2 — stolen-token reuse from a different ASN

**Hypothesis.** If a Kali365 operator captured a victim's tokens via the device code flow, then the access/refresh token will be used from attacker infrastructure (Cloudflare Worker egress AS13335, or rented hosting) that differs from the autonomous system where the victim completed the device-code authorisation — within a short window and persisting beyond a password reset.

**ATT&CK.** T1550.001 (Use Alternate Authentication Material: Application Access Token), T1528 (Steal Application Access Token), T1078.004 (Valid Accounts: Cloud Accounts).

## Prepare

- Telemetry: `SigninLogs` (device-code issuance) joined to `AADNonInteractiveUserSignInLogs` (token-bearing resource access).
- Maintain a hosting/CDN ASN list (13335 Cloudflare, 16509 AWS, 14061 DigitalOcean, 14618 AWS, 396982 Google, 8075 Microsoft-hosted). Roaming/VPN users will shift ASN legitimately — the hosting-ASN constraint is the noise filter.

## Execute

```kql
let window = 60m;
let hostingAsn = dynamic([13335, 16509, 14061, 14618, 396982, 8075]);
let issue = SigninLogs
    | where TimeGenerated > ago(14d)
    | where AuthenticationProtocol == "deviceCode" and ResultType == 0
    | project IssueTime = TimeGenerated, UserPrincipalName, IssueAsn = AutonomousSystemNumber, IssueIP = IPAddress;
let use = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(14d) and ResultType == 0
    | project UseTime = TimeGenerated, UserPrincipalName, UseAsn = AutonomousSystemNumber,
              UseIP = IPAddress, AppDisplayName, ResourceDisplayName;
issue
| join kind=inner use on UserPrincipalName
| where UseTime between (IssueTime .. (IssueTime + window)) and UseAsn != IssueAsn and UseAsn in (hostingAsn)
| project UserPrincipalName, IssueTime, IssueAsn, IssueIP, UseTime, UseAsn, UseIP, AppDisplayName, ResourceDisplayName
| sort by UseTime asc
```

## Analyze

- A single principal whose device-code issuance and follow-on Graph/Office token use come from two different autonomous systems, one of them hosting/CDN, is high-confidence token theft.
- Inspect `ResourceDisplayName` for Microsoft Graph, Exchange Online, and SharePoint — the operator's first move is mailbox and file enumeration.
- Negative result is informative: if device-code users only ever appear from residential/corporate ASNs, the issuance hunt (H1) likely reflects benign device-code use.

## Act

- Revoke refresh tokens and sessions immediately on confirmed hits; resetting the password alone leaves the 90-day refresh token valid.
- Capture the offending IPs/ASNs and block at Conditional Access (named locations) and at the proxy; feed them to H3 and the network rules.
