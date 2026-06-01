---
date: 2026-06-01
title: "GREYVIBE — Russia-nexus AI-augmented espionage against Ukraine: PhantomRelay and LegionRelay PowerShell RATs, FallSpy Android spyware"
clusters: ["GREYVIBE"]
cluster_country: "Russia (nexus; cybercrime overlap)"
techniques_enterprise: [T1566.002, T1204.001, T1059.001, T1059.003, T1059.007, T1027, T1140, T1071.001, T1102.001, T1053.005, T1547.009, T1548.002, T1218.003, T1497.001, T1070.003, T1113, T1560.001, T1555.003, T1041, T1091, T1219, T1021.001, T1496]
techniques_ics: []
platforms: [windows, android, network-edge]
sectors: [government, defense, military, civilian, business]
---

# GREYVIBE — Russia-nexus AI-augmented espionage against Ukraine: PhantomRelay and LegionRelay PowerShell RATs, FallSpy Android spyware

## TL;DR

WithSecure (report 2026-05-28, Mohammad Kazem Hassan Nejad) named **GREYVIBE**, a
previously undocumented Russia-nexus threat group running persistent intelligence
collection against Ukraine and Ukraine-related entities since at least August
2025. The group delivers through spear-phishing (PhantomMail), ClickFix fake
CAPTCHA pages (PhantomClick), and — most distinctively — fake Ukrainian adult-club
websites (PrincessClub) that social-engineer combatants via female personas on
Telegram, then drop **FallSpy** on Android and **PhantomRelay** or **LegionRelay**
PowerShell RATs on Windows. Victimology spans military, government, civilian and
business targets, with confirmed Ukrainian combatant victims concentrated in
Kharkiv. The why-today: GREYVIBE is the freshest named-actor espionage write-up
with public IOCs and YARA, it pairs a fresh Russia-nexus cluster with the repo's
first deep look at **systematic generative-AI tradecraft** (ChatGPT, Gemini,
Ideogram used for lures, obfuscators, full-stack malware and post-compromise
scripts), and design flaws in the LLM-built LegionRelay backend gave researchers
months of visibility — making this a rich, retro-huntable case while infrastructure
is still live.

## Attribution and confidence

| Attribute | Detail |
| --- | --- |
| Primary cluster | GREYVIBE (WithSecure designation; no definitive link to a previously tracked group at time of writing) |
| Nexus | Russia — Russian-speaking operators/developers, Moscow (UTC+3) working hours, Russian-language admin panels and code comments |
| Alignment | Russian state interests: Ukraine-focused intelligence collection in the context of the Russia-Ukraine war |
| Vendor / date | WithSecure Labs, 2026-05-28 |
| Confidence (state alignment) | **high** — targeting, lures, victimology and actions-on-objectives all consistent with intelligence collection vs Ukraine |
| Confidence (cluster identity) | **medium** — newly minted cluster; tooling reused across seemingly unrelated cybercrime activity complicates boundaries |
| Sophistication | low-to-moderate — repeated OPSEC failures, heavy LLM reliance, dev/test samples uploaded to VirusTotal |

### Overlap and genealogy

| Signal | Overlap | Confidence |
| --- | --- | --- |
| PhantomRelayLite reuse | Same base RAT seen in a Microsoft Teams vishing cluster (C2 `thirdmetrics[.]com`) and a KongTuke ClickFix chain (`obmlink[.]com`) | medium — shared tooling, not shared operator |
| ISO builder lineage | Unique ISO builder in early dev samples potentially linked to the TrickBot ecosystem / UAC-0098 | low-to-moderate |
| EDIS Global + compromised domains | Hosting pattern (`bithill[.]com` → NetSupport RAT) shared with reported ClickFix clusters | medium |
| Resource hijacking | XMRig dropped on a small number of LegionRelay hosts (cybercrime tell) | medium |

**Repo genealogy.** GREYVIBE is the sibling of `2026-05-25_UAC0057-OYSTERFRESH-Prometheus-Ukraine`
(Russia-axis espionage vs Ukrainian government) — same theatre, different cluster
and tooling. It is the clearest expression yet of the AI-tradecraft thread running
through `2026-04-26_Bissa-Scanner-React2Shell`, `2026-05-10_Mexico-Water-AI-Assisted-OT`,
`2026-05-28_TrapDoor-CrossEcosystem-Crypto-AI-Stealer`, `2026-05-30_AMOS-OpenClaw-Skill-macOS-Stealer`
and `2026-05-31_BlackShadow-AbabilOfMinab-Recovery-Layer-Destruction`: where those
showed AI compressing a single skill, GREYVIBE shows GenAI woven across the entire
attack lifecycle by a state-aligned actor.

## Kill chain — summary table

| Stage | MITRE | Detail |
| --- | --- | --- |
| Lure | T1566.002 / T1656 | Spear-phish links, fake CAPTCHA (Zoom/LAPAS), fake adult-club sites; female Telegram personas build trust |
| User execution | T1204.001 / T1204.002 | Victim opens archive / runs ClickFix command; decoy (PDF, site, error) shown |
| Loader | T1059.007 / T1027 | .NET / JS / PyInstaller loader; obfuscators LOOKVALJS, DAYLIGHT, TEASOUP, SAWDUST, CRUDEDUST |
| Fingerprint | T1082 / T1033 / T1140 | PowerShell collects host/user/UUID; XOR+base64 (slash→underscore) to C2; history suppressed (T1070.003) |
| RAT | T1059.001 / T1071.001 | PhantomRelay (WebSocket/HTTP) or LegionRelay (REST `/api/*`, Telegram dead drop T1102.001) |
| Persistence | T1053.005 / T1547.009 | Watchdog scheduled task (every 3 min); Startup-folder .lnk; shortcut hijack |
| Privilege escalation | T1548.002 / T1218.003 | Shortcut-hijack UAC via `conhost --headless`; fake "Windows Update" UAC; CMSTP .INF |
| Collection / exfil | T1113 / T1560.001 / T1555.003 / T1041 | Screenshots, staged archives, browser/Telegram/WhatsApp data to `/api/upload` |
| Spread / impact | T1091 / T1496 | USB propagation (`WUDFHost.ps1`); XMRig on a subset; Android FallSpy surveillance |

![GREYVIBE kill chain](./kill_chain.svg)

The diagram's left lane is the victim-side multi-stage Windows chain (lure → loader
→ fingerprint → RAT → persistence → privesc → collection); the right lane is the
GREYVIBE infrastructure and enablers (GenAI tooling, file-sharing delivery,
compromised-domain C2 on EDIS Global, the Telegram dead-drop resolver, and the
Android/HUMINT/cybercrime-overlap layer). The strongest detection anchors are the
`conhost --headless` LOLBIN, the 1-3 minute watchdog task, the on-disk artifact
file names, and the hardcoded user-agents.

## Stage-by-stage detail

### Lure and delivery

GREYVIBE ran at least six PhantomMail spear-phishing campaigns since August 2025.
Emails carried links to ZIP/RAR archives on Google Drive and 4sync, impersonating a
Kyiv City Council official, a Ukrainian energy company, the State Emergency Service,
and the State Service of Special Communications. In October 2025 it briefly used
**PhantomClick** ClickFix fake-CAPTCHA pages (spoofing Zoom and the Latvian LAPAS
site at `lapas[.]live`), instructing victims in Ukrainian to run a "Cloudflare
verification" command. The signature campaign, **PrincessClub**, used fake Ukrainian
adult-club sites delivering FallSpy (Android) or PhantomRelay/LegionRelay (Windows),
with fake female Telegram personas to build trust; later iterations added a
post-infection WebRTC live-call feature to capture victim audio/video — turning the
lure into a HUMINT collection mechanism. Related **DroneLink** sites
(`frontforce[.]org`, `ukrvarta[.]online`, `ukrguard[.]org`) posed as AFU FPV-drone
charities.

### Loader and obfuscation (T1059.007, T1027)

The chain is consistently lure → bundle (ZIP/RAR/NSIS) → loader (.NET/JS/PyInstaller)
→ payload → decoy. The actor rotated custom obfuscators — LOOKVALPS, LOOKVALJS,
DAYLIGHT (PowerShell, from October 2025), TEASOUP (JavaScript, from March 2026) — and
used an arithmetic + charmap obfuscation routine, frequently in combination with
`conhost.exe --headless` to launch PowerShell.

```
# conhost LOLBIN pattern (observed across PhantomMail/PrincessClub/PhantomClick/LegionRelay/PhantomRelay)
conhost.exe --headless powershell.exe -NoProfile -W H -<obfuscated>
```

### PhantomRelay fingerprint (T1082, T1140, T1070.003)

The PhantomRelay initial stage is a PowerShell fingerprinting script (obfuscated by
the C2, with a per-request unique ID). It suppresses history, gathers identity, and
beacons:

```
Set-PSReadlineOption -HistorySaveStyle SaveNothing          # V1; V2 uses: Remove-Module PSReadline -ErrorAction SilentlyContinue
# collects: $env:COMPUTERNAME | Win32_ComputerSystem (domain) | $env:USERNAME | $PID | Win32_ComputerSystemProduct (UUID) | embedded ID
# pipe-join -> XOR(hardcoded key) -> base64 -> '/'->'_' -> append to fetch URL
# e.g. fasterscommunications[.]com/maintenance/<encoded_value>
# UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/534.36 (KHTML, like Gecko) Chrome/95.4.4476.124 Safari/537.36
```

The C2 returns the same-encoded main RAT client, which is executed. PhantomRelayV2
(March 2026) drops the XOR layer, switches UUID retrieval to the registry, and adds
the UA to the RAT client request — cosmetic, LLM-assisted changes to evade signatures.

### RAT: PhantomRelay and LegionRelay (T1059.001, T1071.001, T1102.001)

**PhantomRelay** is a modular PowerShell RAT over WebSockets/HTTP that runs operator
PowerShell and Windows commands; V1 C2 paths include `/maintenance`, `/hoverable`,
`/watchdog`, `/captcha`, `/whereabouts`. **LegionRelay** (first seen in PrincessClub,
December 2025) is a REST-based PowerShell RAT dropped by a .NET loader, persisting via
scheduled task and staging under `%PROGRAMDATA%` (e.g. an `AMD` folder):

```
/api/status     # connectivity check
/api/register   # client registration
/api/commands   # poll for operator PowerShell (run via Invoke-Expression in background jobs)
/api/result     # return output + exit status
/api/upload     # file exfiltration
# on-disk config: client_config.json
# dead-drop resolver (since Mar 2026): fetch encoded C2 from hardcoded Telegram channel,
#   decode each octet by subtracting (4 + octet_index); embedded fallback C2 URL
```

### Persistence (T1053.005, T1547.009)

The PhantomRelay **watchdog** script (served automatically by C2 on infection) saves
the latest watchdog + initial-stage scripts to disk, then creates a scheduled task
that runs **one minute after creation and every three minutes thereafter**,
re-launching the RAT if no active C2 session exists. V1 stages under `%PROGRAMDATA%`;
V2 stages under `%LOCALAPPDATA%`, logs to `razer_update.log` in `%TEMP%`, and uses a
`RazerUpdater/3.0` user-agent. A short-lived late-2025 variant also dropped a Startup
folder `.lnk`.

### Privilege escalation (T1548.002, T1218.003)

LegionRelay operators elevated three ways: **shortcut hijacking** (rewrite a pinned
taskbar/desktop shortcut to launch `starter.ps1` via `conhost.exe --headless`, then
`runas` → UAC prompt the user is primed to accept; `restore.ps1` reverts it); a
**fake "Windows Update"** .NET component registered as scheduled task `Windows Check
Updater` that triggers a UAC prompt and, on approval, re-registers LegionRelay's task
as SYSTEM; and an experimental **CMSTP** UAC bypass via a crafted `.INF`.

### Collection, exfiltration, spread (T1113, T1560.001, T1555.003, T1041, T1091)

Operators enumerated and staged files (documents, configs, certificates, anything
named like "password") into compressed archives and exfiltrated via `/api/upload`;
captured PNG screenshots; and stole browser data (ChromElevator + a custom
LLM-assisted Python stealer) plus Telegram Desktop and WhatsApp Desktop data
(directly or via ZAPiXDESK). A PowerShell **USB propagation** routine drops
`WUDFHost.ps1` under `%PROGRAMDATA%\Microsoft Windows`, hides recent media files, and
plants decoy `.lnk` files; a test archive `архив с фото.rar` with `sync.ps1` (running
`calc.exe`) was found on PrincessClub sites. **FallSpy** (Android, since August 2025)
covertly collects contacts, call logs, installed apps, SIM-linked numbers, device/
network info, Wi-Fi SSID, last-known location, public IP and media.

## RE notes

WithSecure published the canonical hash set and YARA rules on GitHub (see Sources);
the entries below are the durable behavioural fingerprints rather than per-build
hashes, which the actor rotates (often regenerating payloads per request and
refactoring with LLM assistance — by design, to reduce attribution backlinks).

| Component | Lang | Transport | Notes |
| --- | --- | --- | --- |
| PhantomRelay (Lite/V1/V2) | PowerShell | WebSocket / HTTP | XOR+base64 fingerprint; watchdog sched task; UA `Chrome/95.4.4476.124` |
| LegionRelay | PowerShell | REST `/api/*` | `client_config.json`; Telegram dead-drop resolver; IEX in background jobs |
| FallSpy | Android | HTTP params | Surveillanceware; decoy UI; broad PII + media exfil |
| Obfuscators | PS / JS | n/a | LOOKVALPS, LOOKVALJS, DAYLIGHT, TEASOUP, SAWDUST, CRUDEDUST; arithmetic+charmap |

## Detection strategy

### Telemetry that matters

- **Sysmon EID 1 / `DeviceProcessEvents`** — `conhost.exe --headless` with a
  scripting-host child; `schtasks /create /sc minute /mo 1-3` with a `.ps1` action;
  PowerShell `DownloadString`/`IEX` cradles.
- **Sysmon EID 11 / `DeviceFileEvents`** — `WUDFHost.ps1`, `client_config.json`,
  `starter.ps1`, `restore.ps1`, `sync.ps1`, `razer_update.log`.
- **Sysmon EID 3 / `DeviceNetworkEvents`** — beacons to lure/C2 domains; outbound to
  `t.me`/`api.telegram.org` from PowerShell; the hardcoded user-agents.
- **Security 4698 / TaskScheduler Operational** — task creation with minute cadence.
- **PowerShell 4104 (script block)** — history suppression, `Win32_ComputerSystemProduct`,
  `/api/register`, dead-drop decode arithmetic (where script-block logging is enabled).

### Detection coverage

| Engine | File | Logic |
| --- | --- | --- |
| Sigma | `sigma/01_greyvibe_conhost_headless_powershell.yml` | `conhost.exe --headless` launching powershell/pwsh/cmd |
| Sigma | `sigma/02_greyvibe_watchdog_schtask_3min.yml` | `schtasks /create /sc minute /mo 1-3` running a PowerShell action |
| Sigma | `sigma/03_greyvibe_onhost_artifacts_fileevent.yml` | Creation of PhantomRelay/LegionRelay artifact file names |
| KQL | `kql/k1_greyvibe_conhost_headless.kql` | conhost --headless + scripting host (Defender) |
| KQL | `kql/k2_greyvibe_watchdog_schtask.kql` | minute-interval watchdog task creation |
| KQL | `kql/k3_greyvibe_onhost_artifacts.kql` | artifact file-name sweep, counted per host |
| KQL | `kql/k4_greyvibe_c2_egress.kql` | C2/lure domain egress + hardcoded user-agents |
| YARA | `yara/greyvibe_powershell_implants.yar` | PhantomRelay fingerprint, LegionRelay client, watchdog (3 rules) |
| Suricata | `suricata/greyvibe_c2.rules` | RazerUpdater UA, anomalous Chrome UA, PhantomRelayV1 path, LegionRelay `/api/register`, DroneLink DNS (5 sids) |

### Threat hunting hypotheses

- **H1** — `conhost.exe --headless` launching a scripting host (`hunts/peak_h1_conhost_headless_lolbin.md`).
- **H2** — minute-interval scheduled task re-launching user-path PowerShell (`hunts/peak_h2_minute_interval_watchdog_task.md`).
- **H3** — PowerShell download cradles to file-sharing/paste services and Telegram dead-drop resolution (`hunts/peak_h3_powershell_download_cradle_egress.md`).

## Incident response playbook

### First 60 minutes (triage)

1. Confirm the alert: pull the full process tree around any `conhost --headless`
   hit, and the scheduled-task action path for any minute-cadence task.
2. Identify variant: PhantomRelay (watchdog task, `/maintenance`-class paths) vs
   LegionRelay (`client_config.json`, `/api/*`, Telegram resolution).
3. Capture volatile state (running PowerShell, network connections, scheduled tasks)
   before containment changes them.
4. Scope laterally: sweep the fleet with K3 (artifact names) and K1 (conhost) to
   find peers; check for USB propagation (`WUDFHost.ps1`).
5. Triage the user: PrincessClub victims may be combatants groomed via Telegram —
   handle the human factor and any FallSpy-infected phone in parallel.

### Artifacts to collect

| Artifact | Path | Tool | Why |
| --- | --- | --- | --- |
| Watchdog/RAT scripts | `%PROGRAMDATA%` / `%LOCALAPPDATA%` script folders | KAPE / manual | Recover RAT + config |
| LegionRelay config | `client_config.json` | KAPE | C2 + client ID |
| Watchdog log | `%TEMP%\razer_update.log` | KAPE | Execution timeline (V2) |
| Scheduled tasks | `C:\Windows\System32\Tasks\`, Security 4698 | KAPE / EvtxECmd | Persistence + cadence |
| USB launcher | `%PROGRAMDATA%\Microsoft Windows\WUDFHost.ps1` | manual | Spread vector |
| PowerShell logs | Microsoft-Windows-PowerShell/Operational (4104) | EvtxECmd | Script-block content |
| Browser/Telegram/WhatsApp data | user profiles | manual | Confirm exfil scope |

### IR queries and commands

```powershell
# Minute-cadence tasks running PowerShell from user-writable paths
Get-ScheduledTask | ForEach-Object {
  $a = ($_.Actions | Where-Object { $_.Execute -match 'powershell|pwsh|\.ps1' })
  if ($a) { [pscustomobject]@{ Task=$_.TaskName; Path=$_.TaskPath;
    Exec=$a.Execute; Args=$a.Arguments } }
} | Format-List

# Sweep for GREYVIBE on-disk artifacts
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include `
  WUDFHost.ps1,client_config.json,starter.ps1,restore.ps1,sync.ps1,razer_update.log |
  Select-Object FullName,LastWriteTime
```

```kql
// Defender: hosts with both conhost --headless and a minute-cadence task (high confidence)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "conhost.exe" and ProcessCommandLine has "--headless")
     or (FileName =~ "schtasks.exe" and ProcessCommandLine has "minute"
         and ProcessCommandLine has_any ("/mo 1","/mo 2","/mo 3"))
| summarize Signals=make_set(FileName) by DeviceName
| where array_length(Signals) > 1
```

### Containment, eradication, recovery

- **Contain:** isolate the host; block the lure/C2 domains and (carefully) the
  hardcoded user-agents at the proxy; suspend the abused account.
- **Eradicate:** delete the watchdog scheduled task and `Windows Check Updater`
  task; remove staged scripts and Startup `.lnk`; revert hijacked shortcuts; rotate
  credentials for any data reachable via stolen browser/Telegram/WhatsApp sessions.
- **Exit criteria:** no minute-cadence PowerShell task, no artifact files, no C2
  egress for one full watchdog interval (the task re-spawns the RAT every 3 minutes —
  partial cleanup is self-healing).
- **What NOT to do:** do not delete only the running RAT process — the watchdog
  rebuilds it within three minutes; do not treat a PrincessClub victim purely as a
  compromised endpoint while ignoring the Telegram-grooming / FallSpy phone exposure.

### Recovery validation

Re-run K2 and the PowerShell task sweep after cleanup; confirm zero minute-cadence
PowerShell tasks. Re-run K3 across the fleet for residual artifacts. Watch
`DeviceNetworkEvents` for renewed beacons (including Telegram resolution) for at
least 24 hours, since the dead-drop resolver can swing the implant to fresh C2.

## IOCs

| Type | Value | Context | Confidence | Source |
| --- | --- | --- | --- | --- |
| domain | lapas[.]live | PhantomClick fake-LAPAS ClickFix domain | high | WithSecure |
| domain | frontforce[.]org | DroneLink fake-charity lure (LegionRelay) | high | WithSecure |
| domain | ukrvarta[.]online | DroneLink fake-charity lure | high | WithSecure |
| domain | ukrguard[.]org | DroneLink fake-charity lure | high | WithSecure |
| domain | fasterscommunications[.]com | PhantomRelayLite fingerprint C2 (example) | medium | WithSecure |
| domain | saidozdemir[.]com | PhantomRelayLite download cradle (service.html) | medium | WithSecure |
| domain | thirdmetrics[.]com | PhantomRelayLite C2 — Teams vishing overlap (not confirmed GREYVIBE) | medium | WithSecure |
| domain | obmlink[.]com | PhantomRelayLite C2 — KongTuke overlap (not confirmed GREYVIBE) | medium | WithSecure |
| string | RazerUpdater/3.0 | PhantomRelayV2 watchdog user-agent | high | WithSecure |
| string | Chrome/95.4.4476.124 | Hardcoded (non-existent) Chrome build in PhantomRelay UA | high | WithSecure |
| path | %PROGRAMDATA%\Microsoft Windows\WUDFHost.ps1 | USB-propagation launcher | high | WithSecure |
| path | client_config.json | LegionRelay on-disk config | high | WithSecure |
| string | /api/register | LegionRelay REST endpoint (with /status /commands /result /upload) | high | WithSecure |
| string | /watchdog | PhantomRelayV1 watchdog C2 path | high | WithSecure |
| regkey | Windows Check Updater | Fake-update privesc scheduled-task name | medium | WithSecure |

Full indicator set (hashes, additional domains) in `iocs.csv` and at WithSecure's GitHub.

## Secondary findings

- **AI woven across the lifecycle.** GREYVIBE used ChatGPT, Google Gemini and
  Ideogram AI for lure images and sites, obfuscators (LOOKVALJS, DAYLIGHT, TEASOUP),
  full-stack LegionRelay development, and post-compromise scripts. WithSecure
  assesses this is deliberate and operationally integrated — bridging capability
  gaps and reducing the stable artifacts that clustering relies on. One constructed
  script even carried an LLM-agent comment recording the operator's explicit request
  to use `conhost --headless`.
- **The grey zone between crime and state.** PhantomRelayLite appears across
  unrelated cybercrime clusters (Teams vishing, KongTuke), early samples may tie to
  a TrickBot/UAC-0098-linked ISO builder, and XMRig was dropped on some LegionRelay
  hosts — a hybrid posture where state-aligned tasking rides cybercriminal tooling
  and infrastructure.
- **HUMINT pivot in PrincessClub.** A post-infection WebRTC live-call feature on the
  adult-club lure sites could capture victim audio/video, turning a static decoy
  into a human-intelligence collection mechanism against Ukrainian combatants.

## Pedagogical anchors

- **Hunt behaviour, not hashes — especially against AI-built malware.** When an
  actor regenerates and refactors payloads with an LLM per operation, hashes and
  string signatures decay fast. Durable anchors here are LOLBIN shape
  (`conhost --headless`), persistence cadence (every-3-minute task), artifact file
  names, and hardcoded user-agents.
- **Self-healing persistence changes the eradication bar.** A watchdog that
  re-spawns the RAT every three minutes means killing the process is theatre; the
  exit criterion is the absence of the *task*, not the *process*.
- **Shared tooling is not shared identity.** PhantomRelayLite across multiple
  clusters is a reminder to separate the malware family from the operator, and to
  state attribution confidence per signal rather than collapsing everything onto one
  actor.
- **The human is in scope.** PrincessClub grooming and FallSpy mean IR must address
  the targeted person and their phone, not only the Windows endpoint.

## What's in this folder

| File | Purpose |
| --- | --- |
| [README.md](./README.md) | This case write-up |
| [kill_chain.svg](./kill_chain.svg) | Two-lane kill-chain diagram (victim chain vs GREYVIBE infrastructure) |
| [iocs.csv](./iocs.csv) | Indicators: domains, paths, strings, user-agents, infra/tradecraft notes |
| [sigma/01_greyvibe_conhost_headless_powershell.yml](./sigma/01_greyvibe_conhost_headless_powershell.yml) | conhost --headless launching a scripting host |
| [sigma/02_greyvibe_watchdog_schtask_3min.yml](./sigma/02_greyvibe_watchdog_schtask_3min.yml) | Minute-cadence watchdog scheduled task |
| [sigma/03_greyvibe_onhost_artifacts_fileevent.yml](./sigma/03_greyvibe_onhost_artifacts_fileevent.yml) | On-host artifact file names |
| [kql/k1_greyvibe_conhost_headless.kql](./kql/k1_greyvibe_conhost_headless.kql) | Defender: conhost --headless + scripting host |
| [kql/k2_greyvibe_watchdog_schtask.kql](./kql/k2_greyvibe_watchdog_schtask.kql) | Defender: minute-cadence watchdog task |
| [kql/k3_greyvibe_onhost_artifacts.kql](./kql/k3_greyvibe_onhost_artifacts.kql) | Defender: artifact file-name sweep per host |
| [kql/k4_greyvibe_c2_egress.kql](./kql/k4_greyvibe_c2_egress.kql) | Defender: C2/lure domain egress + user-agents |
| [yara/greyvibe_powershell_implants.yar](./yara/greyvibe_powershell_implants.yar) | PhantomRelay fingerprint, LegionRelay client, watchdog |
| [suricata/greyvibe_c2.rules](./suricata/greyvibe_c2.rules) | UA, C2 path and DNS network detections |
| [hunts/peak_h1_conhost_headless_lolbin.md](./hunts/peak_h1_conhost_headless_lolbin.md) | PEAK H1 — conhost --headless LOLBIN |
| [hunts/peak_h2_minute_interval_watchdog_task.md](./hunts/peak_h2_minute_interval_watchdog_task.md) | PEAK H2 — minute-cadence watchdog task |
| [hunts/peak_h3_powershell_download_cradle_egress.md](./hunts/peak_h3_powershell_download_cradle_egress.md) | PEAK H3 — download cradle / Telegram dead drop |

## Sources

- [WithSecure Labs — GREYVIBE: A Russia-nexus group leveraging AI across state-aligned operations](https://labs.withsecure.com/publications/greyvibe)
- [WithSecure — GREYVIBE full report (PDF)](https://labs.withsecure.com/content/dam/labs/docs/WithSecure_GREYVIBE.pdf)
- [WithSecure Labs — GREYVIBE IOCs and YARA (GitHub)](https://github.com/WithSecureLabs/iocs/tree/master/GREYVIBE)
- [The Hacker News — New Russian-Linked GREYVIBE Targets Ukraine with AI-Powered Cyberattacks](https://thehackernews.com/2026/05/new-russian-linked-greyvibe-targets.html)
- [SecurityWeek — Russia-Linked 'GreyVibe' Attackers Use AI to Supercharge Cyberattacks](https://www.securityweek.com/russia-linked-greyvibe-attackers-use-ai-to-supercharge-cyberattacks/)
- [SecurityAffairs — Meet GREYVIBE, the Russian-linked group using AI to target Ukraine](https://securityaffairs.com/192877/apt/meet-greyvibe-the-russian-linked-hacking-group-using-ai-to-target-ukraine-and-still-making-rookie-mistakes.html)
- [SentinelOne Labs — PhantomCaptcha: multi-stage WebSocket RAT targeting Ukraine (related tradecraft)](https://www.sentinelone.com/labs/phantomcaptcha-multi-stage-websocket-rat-targets-ukraine-in-single-day-spearphishing-operation/)
- [MITRE ATT&CK — T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
