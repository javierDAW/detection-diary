# PEAK Hunt H1 - Eight-hour session-refresh cadence from rotating residential proxies

## Hypothesis
A compromised Microsoft 365 account is being kept alive by centralized automation: the
same session recurs at ~8-hour intervals from rotating residential-proxy IPs, reporting
Microsoft Outlook as the client but carrying a non-Edge user agent (Firefox 131.0/151.0 or
Python Requests). If present, at least one account shows a single SessionId spanning
multiple ASNs and countries within a short window.

## Data sources
- Entra ID `SigninLogs` and `AADNonInteractiveUserSignInLogs` (much of this is non-interactive)
- IP intelligence / proxy tagging (e.g. Spur) for residential-proxy classification

## Analytic steps
1. Filter `AppDisplayName == "Microsoft Outlook"` where UserAgent has Firefox/Python and NOT `Edg/`.
2. Group by `SessionId` + `UserPrincipalName`; count distinct `AutonomousSystemNumber` and `Location`.
3. Flag sessions with >= 3 distinct ASNs; inspect inter-sign-in deltas for an ~8h rhythm.
4. Pivot each hit to the initiating interactive sign-in and any `errorCode 90014` OfficeHome events.

## Expected benign
Roaming/VPN users can shift ASN, but rarely across 3+ ASNs with a mechanical 8h cadence and a
Python/Firefox Outlook user agent. Validate against known automation service principals.

## Related detections
- kql/entra_session_id_across_asns.kql
- sigma/entra_outlook_nonedge_session_refresh.yml
- sigma/entra_officehome_error_90014.yml
