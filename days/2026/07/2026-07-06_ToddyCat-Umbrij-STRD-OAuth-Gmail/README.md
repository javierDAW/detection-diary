---
date: 2026-07-06
title: "ToddyCat Umbrij: Shadow Token via Remote Debug steals OAuth tokens to read Gmail"
clusters: ["ToddyCat"]
cluster_country: "China-nexus"
techniques_enterprise: [T1053.005, T1574.001, T1036.005, T1134.003, T1005, T1539, T1550.001, T1528, T1114.002]
techniques_ics: []
platforms: [windows, cloud-multi]
sectors: [government, defense, telecommunications]
category: espionage
---

# ToddyCat Umbrij: Shadow Token via Remote Debug steals OAuth tokens to read Gmail

## TL;DR
Kaspersky's Securelist published Part 2 of its ToddyCat email-theft research on 2026-06-30, detailing a
new .NET tool the group calls **Umbrij** and a technique they name **Shadow Token via Remote Debug
(STRD)**. Instead of decrypting stored credentials, Umbrij rides a victim's *live* Google session: it
copies the browser profile, launches Chromium **headless with a remote debugging port**, drives it over
the DevTools protocol with PuppeteerSharp, and clicks through an OAuth consent to mint an authorization
code that is exchanged off-host for an access token to Gmail, Contacts, Calendar and Drive. To blend in,
the OAuth request reuses the client IDs of Google's own Outlook migration apps (GWMMO/GWSMO). The tool
was found via Kaspersky MDR threat hunting; the underlying activity dates to 2025 (the vendor's Sigma
rules are stamped Aug and Dec 2025), and what is fresh this week is the consolidated public write-up.
ToddyCat is a China-nexus cyber-espionage cluster that has historically targeted government, defense and
telecom entities across Europe and Asia; Part 2 does **not** name the specific victims of this campaign.

## Attribution and confidence
**Cluster:** ToddyCat. **Aliases/overlaps:** tracked by Kaspersky as ToddyCat; the group is a
Chinese-speaking espionage actor first detailed by Kaspersky in 2022. **Attribution confidence: medium**
for the Umbrij/STRD tooling being ToddyCat (Kaspersky attributes on TTP continuity, not on shared C2 or
a hard external corroboration in this article). Attribution reasoning: long-standing reliance on **DLL
sideloading** to drop utilities via scheduled tasks, and the explorer.exe **token-impersonation**
mechanism that is **identical to the group's prior TomBerBil tool**.

| Overlap signal | Detail | Weight |
|---|---|---|
| DLL sideloading via signed loaders + scheduled task | Group signature since 2022 | Medium |
| Token impersonation identical to TomBerBil | Same CreateProcessAsUserW/RevertToSelf flow | Medium |
| Email-theft objective (Part 1: Outlook; Part 2: Gmail) | Continuity of collection goal | Medium |

**Genealogy with previous repo cases.** This is the repo's first ToddyCat case and first case anchored
on the STRD / remote-debug OAuth technique. It extends the repo's OAuth-abuse thread -
`2026-04-28_clase_consentfix_oauth_entra_id` (consent phishing on Entra ID),
`2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion` (OAuth token theft against Salesforce) and
`2026-07-01_AWS-Console-AiTM-input24-PhishingKit` (AiTM token theft) - but the vector is novel: no
phishing, no AiTM proxy, no stored-credential decryption. It is a **host-side** theft of a *live* cloud
session. DLL-sideloading genealogy overlaps thematically with `2026-06-26_GentleKiller-BYOVD` (trusted
binaries abused) though the mechanism differs.

## Kill chain — summary table
| Stage | MITRE | Detail |
|---|---|---|
| Persistence via masquerading task | T1053.005, T1036.005 | Scheduled task `KasperskyEndpointSecurityEDRAvp` launches a signed loader |
| DLL sideload of Umbrij | T1574.001 | Signed loader in a staging dir loads the malicious .NET DLL (ConfuserEx) |
| Token impersonation | T1134.003 | Duplicate an explorer.exe token, retain privileges (as in TomBerBil) |
| Copy live browser profile | T1539, T1005 | Parse Local State info_cache, copy cookies/Login Data to `BackupFiles` |
| Headless browser + debug port | T1550.001 | Launch Chromium `--headless --remote-debugging-port`, drive via DevTools |
| Mint OAuth authorization code | T1528 | PuppeteerSharp clicks account + "Allow"; capture `code=` from localhost redirect |
| Read Gmail via Google API | T1114.002 | Exchange code for an access token off-host; read mail/contacts/calendar/drive |

![ToddyCat Umbrij STRD kill chain](./kill_chain.svg)

The left lane is the victim workstation from foothold to Gmail read; the right lane is ToddyCat's
operations - deploy Umbrij, masquerade + sideload, the STRD design, blending into GWMMO/GWSMO, log
retrieval and the off-host token exchange. The purple cross-lane arrows mark the three highest-fidelity
detection anchors: token impersonation, the headless-browser-with-debug-port launch, and the OAuth grant
to a migration app.

## Stage-by-stage detail

### 1. Persistence via a masquerading scheduled task
Execution was observed as a scheduled task named `KasperskyEndpointSecurityEDRAvp`. Kaspersky products
do not create a task with that name, so it is a masquerade (T1036.005) that launches a digitally signed
loader on a schedule.

```
Task: KasperskyEndpointSecurityEDRAvp  ->  signed loader (e.g. BDSubWiz.exe)
```

### 2. DLL sideload of Umbrij
The signed loader uses DLL search-order hijacking to load the Umbrij DLL from the same folder. Umbrij is
a .NET/MSIL DLL obfuscated with ConfuserEx. Observed loader -> DLL pairs and staging paths:

```
C:\Users\Public\BDSubWiz.exe            -> C:\Users\Public\log.dll
C:\Windows\Vss\bds.exe                  -> C:\Windows\Vss\log.dll
C:\Windows\Temp\GoogleDesktop.exe       -> C:\Windows\Temp\GoogleServices.DLL
C:\Windows\Temp\VSTestVideoRecorder.exe -> ...\Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.dll
```

Observed command line: `"c:\Users\Public\BDSubWiz.exe" -regex <name> -deepsearch`.

### 3. Token impersonation
Umbrij finds `explorer.exe`, duplicates its token retaining all privileges, and runs as that user - the
exact mechanism used by the group's TomBerBil tool. Flags `-user <name>` and `-runas-currentuser` control
whose token is used.

```
[*] Impersonate <username> success!   ->  CreateProcessAsUserW ... RevertToSelf succeed!
```

### 4. Copy the live browser profile
Umbrij reads the browser `Local State`, parses the `info_cache` array, and selects profiles whose
`user_name` holds an email address (an active Google login). It copies IndexedDB, Local Storage, Network,
Login Data, Preferences and Web Data into a `BackupFiles` directory so it can drive a *copy* of the live,
still-authenticated profile without disturbing the user's own window.

```
%LOCALAPPDATA%\Google\Chrome\BackupFiles\
%LOCALAPPDATA%\Microsoft\Edge\User Data\BackupFiles\
```

### 5. Headless browser with a remote debugging port
Umbrij launches the browser against the copied profile in headless mode with a debug port, then connects
over the Chrome DevTools protocol using PuppeteerSharp. Because the copied session is still authenticated,
no login prompt appears.

```
"<browser>" --user-data-dir="...\BackupFiles" --remote-debugging-port=11111 --profile-directory="Default" --headless https://www.google.com/
```

### 6. Mint the OAuth authorization code
Over DevTools, Umbrij issues a GET to the Google OAuth 2.0 authorization endpoint, uses JavaScript to
click the account and the "Allow" button, and extracts the authorization code from the `localhost`
redirect (the substring between `code=` and `&scope`). It writes the code to a log for the operator.

```
/o/oauth2/v2/auth/identifier?response_type=code&client_id=279448736670.apps.googleusercontent.com
   &redirect_uri=http%3A%2F%2Flocalhost&scope=...mail.google.com...&flowName=GeneralOAuthFlow
```

The request is distinguishable from the legitimate GWMMO/GWSMO flow: it carries `flowName=GeneralOAuthFlow`,
uses `redirect_uri=http://localhost` (legit uses `http://localhost:61619/callback`), and **omits PKCE
(`code_challenge`), `state` and `login_hint`**.

### 7. Read Gmail via the Google API
The authorization code is exchanged for an access token off-host, and the token reaches the mailbox via
the Google API. The requested scopes span full Gmail (`https://mail.google.com/`), `gmail.insert`,
`gmail.labels`, Contacts, Calendar, Drive and `admin.directory.*` - a broad correspondence-collection
grant. `-sync` swaps the client ID to GWSMO (`1095133494869`).

## Detection strategy

### Telemetry that matters
- **Sysmon EID 1 / Defender `DeviceProcessEvents`:** full command line of chrome.exe / msedge.exe (catch
  `--remote-debugging-port` + `--headless`) and of schtasks.exe (catch the masquerading task name).
- **Sysmon EID 7 / Defender `DeviceImageLoadEvents`:** the sideloaded DLL name loaded from a staging path.
- **Sysmon EID 11:** creation of `log.dll` / `GoogleServices.DLL` in Public/Temp/Vss, and of the
  `BackupFiles` profile copy.
- **Google Workspace audit / Defender for Cloud Apps `CloudAppEvents`:** OAuth token grants to the GWMMO
  (`279448736670`) and GWSMO (`1095133494869`) client IDs and subsequent Gmail API reads.

### Detection coverage
| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/umbrij_browser_remote_debug_headless.yml | Browser cmdline has `--remote-debugging-port` AND `--headless` |
| Sigma | sigma/umbrij_dll_sideload_signed_loader.yml | Known signed loader running from a staging dir |
| Sigma | sigma/umbrij_masquerading_scheduled_task.yml | schtasks/PowerShell referencing `KasperskyEndpointSecurityEDRAvp` |
| KQL | kql/umbrij_headless_remote_debug.kql | Headless + debug-port browser; flags `BackupFiles` user-data-dir |
| KQL | kql/umbrij_dll_sideload.kql | Loader -> known sideloaded DLL from a staging path (ImageLoad) |
| KQL | kql/umbrij_masquerading_task.kql | Masquerading task via process + ScheduledTaskCreated |
| KQL | kql/umbrij_gwmmo_gwsmo_oauth_grant.kql | OAuth grant to GWMMO/GWSMO client IDs in CloudAppEvents |
| YARA | yara/umbrij.yar | Umbrij OAuth/log strings + STRD behavioural heuristic |
| Suricata | suricata/umbrij.rules | Decrypted OAuth request markers + loopback DevTools (see caveats) |

### Threat hunting hypotheses
- **H1** — Chromium launched headless with a remote debugging port on a non-automation host. See
  [peak_h1_headless_remote_debug.md](./hunts/peak_h1_headless_remote_debug.md).
- **H2** — Signed loader sideloads Umbrij from a staging dir + masquerading task. See
  [peak_h2_dll_sideload_masquerade.md](./hunts/peak_h2_dll_sideload_masquerade.md).
- **H3** — Unexpected OAuth grant to GWMMO/GWSMO and Gmail API reads. See
  [peak_h3_gwmmo_gwsmo_oauth_grant.md](./hunts/peak_h3_gwmmo_gwsmo_oauth_grant.md).

## Incident response playbook

### First 60 minutes (triage)
1. Confirm the browser process: was chrome.exe/msedge.exe launched with `--remote-debugging-port` and
   `--headless`, and what was its parent process?
2. Check for a `BackupFiles` directory under the user's Chrome/Edge User Data.
3. Enumerate scheduled tasks for `KasperskyEndpointSecurityEDRAvp` and identify the launched loader/DLL.
4. In Google Workspace, list OAuth grants to GWMMO/GWSMO for the affected user; check recent Gmail/Drive
   API read volume.
5. If confirmed, **revoke the OAuth grant** immediately (this invalidates the token) and isolate the host.

### Artifacts to collect
| Artifact | Path | Tool | Why |
|---|---|---|---|
| Process creation logs | Sysmon EID 1 / DeviceProcessEvents | KAPE/EDR | Browser flags + task creation |
| Image load logs | Sysmon EID 7 / DeviceImageLoadEvents | KAPE/EDR | Sideloaded DLL + path |
| Sideloaded DLL + loader | Public / Windows\Temp / Windows\Vss | KAPE | Sample the Umbrij DLL |
| Profile copy | `%LOCALAPPDATA%\...\BackupFiles` | KAPE | Confirms session riding |
| Scheduled task | `%WINDIR%\System32\Tasks` + TaskCache | KAPE | Persistence and action |
| Google audit logs | Workspace Admin / CloudAppEvents | Admin console | OAuth grant + API reads |

### IR queries and commands
```powershell
# Scheduled task masquerading as Kaspersky
Get-ScheduledTask | Where-Object { $_.TaskName -eq 'KasperskyEndpointSecurityEDRAvp' } | Format-List *
# Any BackupFiles profile copies
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome","$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Recurse -Directory -Filter 'BackupFiles' -ErrorAction SilentlyContinue
# Sideloaded DLL candidates in staging dirs
Get-ChildItem C:\Users\Public,C:\Windows\Temp,C:\Windows\Vss -Include log.dll,GoogleServices.DLL -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5
```
```kql
DeviceProcessEvents
| where FileName in~ ("chrome.exe","msedge.exe")
| where ProcessCommandLine has "--remote-debugging-port" and ProcessCommandLine has "--headless"
```

### Containment, eradication, recovery
Revoke the GWMMO/GWSMO OAuth grant at `myaccount.google.com/connections` (or org-wide in the Admin
console) - this invalidates all issued tokens; a password reset alone does **not** kill an existing
token. Remove the scheduled task and the sideload loader + DLL, and force re-authentication.
**Exit criteria:** no headless/debug-port browser launches, no BackupFiles copies, no residual OAuth
grants to migration apps the org does not use. **What NOT to do:** do not merely delete the DLL and
leave the token live - the attacker keeps mailbox access via the API until the grant is revoked.

### Recovery validation
Confirm the OAuth grant is gone and no new Gmail API reads originate from unexpected clients; verify no
`--remote-debugging-port --headless` browser launches recur; audit third-party Google app grants across
users; consider the Chrome policy `DeveloperToolsAvailability=2` on non-developer hosts.

## IOCs
Top indicators (full list in [iocs.csv](./iocs.csv)). No attacker C2 domain or IP is published - exfil
is the operator manually retrieving the local log holding the authorization code.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| md5 | 1ab58838e5790efb22f2d35ab98c0b7d | Umbrij ver. a | high | Securelist 2026-06-30 |
| md5 | 22aaeb4946ba6d2f2e27feb7dbb295de | Umbrij ver. b | high | Securelist 2026-06-30 |
| md5 | f169d6d172dfb775895a5e2b1540c854 | Umbrij ver. c | high | Securelist 2026-06-30 |
| md5 | 9f5f2f0fb0a7f5aa9f16b9a7b6dad89f | GoogleDesktop.exe loader | high | Securelist 2026-06-30 |
| md5 | 28cb7b261f4eb97e8a4b3b0d32f8def1 | BDSubWiz.exe loader | high | Securelist 2026-06-30 |
| md5 | bae82a15d1dbfb024617b9b56a8e5f66 | VSTestVideoRecorder.exe loader | high | Securelist 2026-06-30 |
| string | KasperskyEndpointSecurityEDRAvp | Masquerading scheduled task | high | Securelist 2026-06-30 |
| string | 279448736670.apps.googleusercontent.com | GWMMO client_id abused | high | Securelist 2026-06-30 |
| string | 1095133494869 | GWSMO client_id (with -sync) | high | Securelist 2026-06-30 |
| string | flowName=GeneralOAuthFlow | Marker absent from legit flow | medium | Securelist 2026-06-30 |
| path | %LOCALAPPDATA%\...\BackupFiles | Copied live profile | high | Securelist 2026-06-30 |

**CVE / KEV status:** this campaign involves **no CVE** - it abuses legitimate OAuth and browser
features, not a software vulnerability. There is therefore no CISA KEV cross-reference for this case and
no `kev.md` is generated.

## Secondary findings
- **This is Part 2 of a collection campaign, not a one-off.** Part 1
  ([Securelist, TomBerBil / Outlook](https://securelist.com/toddycat-apt-steals-email-data-from-outlook/118044/))
  covered ToddyCat stealing data from browsers and from local and cloud email (Outlook). Umbrij extends
  the same objective - corporate correspondence - to Gmail. Defenders should treat email theft as a
  program with multiple tools, not a single IOC set.
- **Legitimate Google apps as cover.** By reusing the OAuth client IDs of Google's own Outlook migration
  tools (GWMMO/GWSMO), the grant looks routine to anyone glancing at the third-party-apps list. The tell
  is the *request shape* (no PKCE/state/login_hint, `flowName=GeneralOAuthFlow`) and the *absence of a
  matching migration project*, not the app name.
- **STRD generalizes beyond ToddyCat.** Riding a live session via a headless browser and the DevTools
  remote-debugging port is a technique any actor can copy; it sidesteps DPAPI, cookie encryption and even
  hardware-bound token protections because it never extracts the secret - it borrows the session. Expect
  copycats; detect at the launch and the grant.

## Pedagogical anchors
- **Token theft beats credential theft.** Umbrij never cracks a password or decrypts a cookie - it
  borrows the *live* authenticated session. Detections that watch credential stores miss it; watch the
  browser launch flags and the OAuth grant instead.
- **A remote debugging port is a red flag on a user host.** `--remote-debugging-port` + `--headless`
  together, spawned by something other than explorer.exe or a known automation service, is high-signal
  and cheap to hunt.
- **Trusted vendor names are attacker cover.** A "Kaspersky" task, a "Google"/"Bitdefender"/"Visual
  Studio" signed loader - name-based allowlisting fails here. The anomaly is the *location* and the
  *co-located unsigned DLL*.
- **Revoke the grant, not just the password.** For stolen OAuth tokens, revoking the app grant is the
  fast containment; a password reset does not invalidate an existing access token.
- **Freshness honesty.** The activity is from 2025; the *publication* is 2026-06-30. Treat the hashes as
  durable and the technique as current, but do not imply a live 2026 intrusion.

## What's in this folder
| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane STRD kill chain (Template A, espionage accent). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | Hashes, loaders, paths, OAuth client IDs and markers. | [iocs.csv](./iocs.csv) |
| sigma/umbrij_browser_remote_debug_headless.yml | Headless + remote-debug-port browser launch. | [file](./sigma/umbrij_browser_remote_debug_headless.yml) |
| sigma/umbrij_dll_sideload_signed_loader.yml | Signed loader from a staging dir. | [file](./sigma/umbrij_dll_sideload_signed_loader.yml) |
| sigma/umbrij_masquerading_scheduled_task.yml | KasperskyEndpointSecurityEDRAvp task. | [file](./sigma/umbrij_masquerading_scheduled_task.yml) |
| kql/umbrij_headless_remote_debug.kql | Headless/debug-port browser hunt. | [file](./kql/umbrij_headless_remote_debug.kql) |
| kql/umbrij_dll_sideload.kql | Loader -> sideloaded DLL hunt. | [file](./kql/umbrij_dll_sideload.kql) |
| kql/umbrij_masquerading_task.kql | Masquerading task hunt. | [file](./kql/umbrij_masquerading_task.kql) |
| kql/umbrij_gwmmo_gwsmo_oauth_grant.kql | OAuth grant to migration apps. | [file](./kql/umbrij_gwmmo_gwsmo_oauth_grant.kql) |
| yara/umbrij.yar | Umbrij strings + STRD heuristic. | [file](./yara/umbrij.yar) |
| suricata/umbrij.rules | OAuth request + loopback DevTools (with caveats). | [file](./suricata/umbrij.rules) |
| hunts/peak_h1_headless_remote_debug.md | PEAK hunt H1. | [file](./hunts/peak_h1_headless_remote_debug.md) |
| hunts/peak_h2_dll_sideload_masquerade.md | PEAK hunt H2. | [file](./hunts/peak_h2_dll_sideload_masquerade.md) |
| hunts/peak_h3_gwmmo_gwsmo_oauth_grant.md | PEAK hunt H3. | [file](./hunts/peak_h3_gwmmo_gwsmo_oauth_grant.md) |

## Sources
- [How the ToddyCat APT group gains access to Gmail accounts — Securelist (2026-06-30)](https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/)
- [ToddyCat APT steals email data from Outlook (Part 1) — Securelist](https://securelist.com/toddycat-apt-steals-email-data-from-outlook/118044/)
- [ToddyCat-Linked Umbrij Malware Abuses OAuth to Access Gmail via Google API — The Hacker News (2026-07-02)](https://thehackernews.com/2026/07/toddycat-linked-umbrij-malware-abuses.html)
- [ToddyCat Uses Shadow Token via Remote Debug to Compromise Gmail Accounts — GBHackers](https://gbhackers.com/toddycat-uses-shadow-token/)
- [ToddyCat: Unveiling an unknown APT actor attacking high-profile entities in Europe and Asia — Securelist (2022)](https://securelist.com/toddycat/106799/)
- [MITRE ATT&CK T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
