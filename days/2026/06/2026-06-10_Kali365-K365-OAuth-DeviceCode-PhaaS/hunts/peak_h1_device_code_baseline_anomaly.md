# PEAK Hunt H1 — device-code sign-in baseline and anomaly

**Hypothesis.** If Kali365 phished a user in our tenant, then a standard interactive user will have completed an Entra ID sign-in using the OAuth 2.0 device code protocol — a flow that, in most enterprises, is used only by a small, stable set of input-constrained devices and service identities. The long tail of one-off human users completing device code auth is the hunt surface.

**ATT&CK.** T1528 (Steal Application Access Token), T1078.004 (Valid Accounts: Cloud Accounts), T1566.002 (Spearphishing Link).

## Prepare

- Telemetry: Microsoft Sentinel `SigninLogs` / Defender XDR `AADSignInEventsBeta`, field `AuthenticationProtocol == "deviceCode"`.
- Build the allow-baseline first: which UPNs and `AppDisplayName` values legitimately use device code (smart TVs, Teams Rooms, printers, Azure CLI / kubectl users, CI runners). These are the exclusions, not the findings.

## Execute

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode" and ResultType == 0
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10),
            ASNs = make_set(AutonomousSystemNumber, 10), Cities = make_set(Location, 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by UserPrincipalName
| extend DaysActive = datetime_diff('day', LastSeen, FirstSeen)
| where SignIns <= 3 and DaysActive <= 2
| sort by FirstSeen desc
```

## Analyze

- Rare, recent, low-count device-code users who are normal humans (mailbox-enabled, licensed, not kiosk/service) are the priority. A first-ever device-code sign-in for a knowledge worker is the diagnostic anomaly.
- Enrich each hit with the resource accessed (`ResourceDisplayName`) and the app — Kali365 issues tokens to public-client apps targeting Microsoft Graph / Office 365.
- Pivot positives to H2 to confirm token theft via cross-ASN reuse.

## Act

- For each confirmed phish: revoke all refresh tokens for the user (`Revoke-MgUserSignInSession` / "Revoke sessions"), force re-registration of MFA, and reset the password — in that order, because the refresh token survives a password reset alone.
- Hunt the user's mailbox for new inbox rules and any sent mail in the dwell window (H3 / the mailbox KQL rule). Add device-code Conditional Access restrictions tenant-wide.
