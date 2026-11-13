# PEAK hunt H1 - Fake help desk on Teams: external contact, Quick Assist session, then a portable runtime staged under the user profile

## Prepare

- **Hypothesis:** an external party, chatting or calling from an organization-themed `onmicrosoft.com` tenant with a support-style display name, convinced one or more users to open Quick Assist and read out the connection code; within the following hour an archive landed in the user's Downloads folder, was extracted to a `KB`-prefixed staging directory under the profile, and a portable Bun, Java or Python runtime ran the payload, then the workstation started talking LDAPS (636) and SMB (445) to domain infrastructure.
- **Why:** Microsoft Security Research (2026-10-30) investigated two unattributed intrusions that both started this way; no Teams vulnerability was used, only external collaboration and social engineering. Defender raised Teams-centric alerts (for example "Microsoft Teams chat initiated by a suspicious external user", "Possible Teams phishing affecting more than two users", "Suspicious JavaScript process"). In one case the foothold became AD CS ESC1 abuse and domain-wide credential theft within hours (see H2/H3).
- **Honesty:** Microsoft published no tenant names, display names, archive names, staging path, runtime file names or network indicators; only three SHA-256 values of initial-access scripts (one JavaScript, two Python - see `iocs.csv`). The `KB<digits>` folder under `AppData\Roaming` comes from a secondary summary and is unverified. The Teams `CloudAppEvents` ActionType names used in k1 are unverified. Microsoft's own hunting query text was not available.
- **Scope:** 30 days of Teams audit data (`CloudAppEvents` / `OfficeActivity`), `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` for all user workstations; Teams external access configuration of the tenant.
- **Confidence:** medium for external Teams contact followed by Quick Assist on the same user; medium for a renamed Bun or `java.exe` launching a `.java` file from the profile; low for the `\KB` path alone; high for the published hashes.

## Execute

**Data sources / content:** `sigma/01_quick_assist_launched_on_endpoint.yml`, `sigma/02_portable_runtime_from_user_profile_kb_staging_or_renamed_bun.yml`, `kql/k1_teams_external_helpdesk_contact_then_quick_assist_and_defender_alerts.kql`, `kql/k2_staged_portable_runtime_kb_directory_and_domain_ldaps_smb_contact.kql`, `yara/bun_runtime_and_renamed_rclone_hunting.yar` (rule 1).

1. Check exposure first (read-only): which external tenants can reach your users and whether Quick Assist is even allowed.

```powershell
# Author: Jarmi
Connect-MicrosoftTeams
Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains, BlockedDomains, AllowTeamsConsumer, AllowTeamsConsumerInbound
Get-CsExternalAccessPolicy | Select-Object Identity, EnableFederationAccess, EnableTeamsConsumerAccess
```

2. Run k1. Fill `<add_known_partner_tenant_ids>` and `<add_known_helpdesk_upns>`; review `MicrosoftArticleAlert` first, then `ExternalTeamsThenQuickAssist` rows flagged `high` (onmicrosoft.com sender or support-style name).
3. Before trusting k1, confirm which Teams ActionTypes your tenant actually emits: `CloudAppEvents | where Application == "Microsoft Teams" | summarize count() by ActionType`.
4. For every matching user/device, run k2 around the Quick Assist time and look for archive writes in `Downloads`, a new `KB*` folder under the profile, a runtime with a mismatched `OriginalFileName`, and discovery (`ipconfig`, `tasklist`, version query) followed by 636/445 connections.
5. On a suspect device, list KB-named folders and runtimes under profiles (read-only) and scan them with YARA rule 1:

```powershell
# Author: Jarmi
Get-ChildItem -Path C:\Users\*\AppData -Directory -Recurse -Depth 3 -Filter 'KB*' -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc
Get-ChildItem -Path C:\Users\* -Recurse -Include bun.exe,java.exe,javaw.exe,python.exe,*.java -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTimeUtc, @{n='Original';e={$_.VersionInfo.OriginalFilename}}
```

## Act

- **Expected benign:** real help desk sessions (ticket exists, internal sender), external partners in allow-listed tenants, developers with portable runtimes.
- **Action on match:** treat external-help-desk-then-Quick-Assist plus a staged runtime as hands-on-keyboard compromise. Isolate the device, end the user's sessions and revoke refresh tokens, collect the staging folder and the archive, then pivot immediately to H2 (certificate requests by this user / device) and H3.
- **Hardening:** restrict external Teams access to allow-listed domains, block or alert on Teams consumer and unknown tenants, restrict remote-support tools to one approved product (App Control / WDAC to block Quick Assist where unused), and train users to verify support requests out-of-band.
- **Detections:** keep Sigma 01 as low-severity telemetry correlated in the SIEM (k1); promote Sigma 02 renamed-Bun selection to an alert.
- **Exit criteria:** every Quick Assist session in the window maps to a ticket or is investigated; no unexplained `KB*` staging folders with runtimes remain.
