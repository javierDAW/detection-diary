# PEAK Hunt H3 — C2 on hijacked legitimate infrastructure

**Author:** Jarmi · **Date:** 2026-08-14 · **ATT&CK:** T1071.001 (Web Protocols), T1102.002 (Web Service), T1584.004 (Compromise Infrastructure: Server), T1090 (Proxy)

## Hypothesis
If C2 is live, then compromised hosts beacon to Microsoft Graph/OneDrive from non-browser processes (MISTPEN) and/or to the Enveil-impersonation domains and C2 IPs (ForestTiger/Troy), and your own internet-facing Roundcube/WordPress/PrestaShop may host the RelayShell web shell.

## Prepare
- Data sources: proxy/firewall/DNS logs, Defender XDR `DeviceNetworkEvents`; web-server access logs and webroot file listings for internet-facing CMS/webmail.
- Scope: all endpoints for client beacons; all internet-facing Roundcube/WordPress/PrestaShop for server-side web shells.
- Baseline: which processes legitimately talk to Graph/OneDrive (browsers, Office, OneDrive client, Teams).

## Execute
1. Beacons to `graph.microsoft.com`/`onedrive.live.com`/`1drv.ms` from processes that are not browsers/Office/OneDrive (see `kql/lazarus_dreamjob_c2_indicators.kql`).
2. DNS/connections to `envell.xyz`, `enveil.online`, `uxtramine.org` and to `135.181.67.203` / `135.181.185.158` (Sigma `net_lazarus_dreamjob_c2.yml`; Suricata rules).
3. Server-side: unpatched Roundcube (CVE-2025-49113); RelayShell PHP web shell (hashes `21c3ad48...`, `cc4e06aa...`) and file-based command-relay artifacts (paired request/response text files) in the webroot.
4. Egress via ExpressVPN ranges from management planes that should never use consumer VPNs.

## Act
- Client beacon confirmed: isolate, feed the host into H1/H2.
- Server web shell confirmed: take offline / forensically image, remove RelayShell, patch CVE-2025-49113, rotate all credentials that touched the server.

## Notes
The C2 hides inside legitimate, reputable domains and your own partners' infrastructure — reputation and allow-listing will not catch it; anchor on *which process* is beaconing and on server-side web-shell artifacts.
