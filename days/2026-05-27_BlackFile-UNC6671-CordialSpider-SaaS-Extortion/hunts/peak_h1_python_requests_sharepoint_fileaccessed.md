# PEAK Hunt H1 — Scripting-library User-Agent against SharePoint or OneDrive API

## Hypothesis

If UNC6671 / BlackFile / Cordial Spider tradecraft is present in the environment,
then the Microsoft 365 Unified Audit Log will contain `FileAccessed` or
`FileDownloaded` events (workload SharePoint or OneDrive) whose `UserAgent`
string identifies a scripting library (`python-requests`, `WindowsPowerShell`,
`curl`, `Go-http-client`, `aiohttp`, `httpx`, `node-fetch`, `axios`) and whose
source IP is on a commercial VPN or residential-proxy ASN that is not on the
managed-device list.

## Why this discriminates

GTIG (2026-05-15) documented that UNC6671 deliberately downshifted in later
intrusions from issuing the request pattern that emits `FileDownloaded` to the
direct HTTP GET pattern that emits `FileAccessed`. Most SOCs treat
`FileAccessed` as background browsing noise and alert only on `FileDownloaded`.
The discriminator is not the `Operation` field — it is the `UserAgent` string.
A SharePoint or OneDrive workload event carrying a scripting-library
User-Agent is, in normal enterprise usage, a near-zero baseline; almost all
legitimate access is a browser, the Office native client, or Microsoft Graph
SDKs that advertise themselves by SDK identity. The combination of
`UserAgent contains "python-requests"` and `Workload in (SharePoint, OneDrive)`
is therefore high-confidence in the absence of approved automation.

## Expected benign

- Legitimate compliance / e-discovery tooling that pulls SharePoint content
  using a Python or PowerShell SDK. Identify by `UserId` (service account),
  `ClientIP` (corporate egress), and managed-device flag.
- Authorized M365 backup vendors (Veeam, AvePoint, Druva) issuing API calls
  from a documented egress range. Allowlist by ClientIP block.
- Custom internal automation reading SharePoint as part of an integration
  pipeline. Validate against the application allowlist.

## Expected malicious

- The User-Agent carries the literal `python-requests/2.28.1` string (or the
  PowerShell variant).
- The ClientIP belongs to a commercial VPN, residential proxy or hosting
  provider ASN (Hostwinds, Cogent, Datacamp, Mullvad, Surfshark, etc.).
- The user is a human (not a service account) and the access pattern is
  programmatic — hundreds to thousands of distinct file objects in a short
  window.
- The `AppAccessContext.ClientAppId` is spoofed as
  `d3590ed6-52b3-4102-aeff-aad2292ab01c` ("Microsoft Office") but the
  `UserAgent` still identifies the scripting library.

## Actions

1. Run `kql/k1_m365uan_fileaccessed_python_useragent.kql` against the last
   30 days.
2. For each hit, pivot on the `UserId` to enumerate all sign-in activity in
   the same window (Entra ID `SigninLogs`).
3. Pull `AuditLogs` for the same user for any MFA-method registration or
   inbox-rule creation in the 24 hours preceding the burst.
4. If the User-Agent + unfamiliar ClientIP + spoofed ClientAppId triad is
   confirmed, trigger the IR playbook: revoke sessions, remove attacker MFA
   device, delete suspect inbox rules, block lookalike subdomain at egress.
5. Expand the hunt window to 24 months for retro-detection of the BlackFile
   mid-rebrand period (see README — operator confirmed shutdown under brand
   2026-05-11).
