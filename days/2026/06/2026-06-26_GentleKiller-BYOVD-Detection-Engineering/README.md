---
date: 2026-06-26
title: "GentleKiller BYOVD Suite: Behavioral Detection Engineering Against Operator-Maintained EDR Killers"
clusters: ["The Gentlemen RaaS (GentleKiller operator)"]
cluster_country: "Unknown — e-crime, financially motivated"
techniques_enterprise: [T1543.003, T1106, T1036, T1036.001, T1027, T1562.001, T1685, T1552.001, T1059.003, T1105]
techniques_ics: []
platforms: [windows]
sectors: [technology, finance, healthcare, manufacturing, legal, government]
---

# GentleKiller BYOVD Suite: Behavioral Detection Engineering Against Operator-Maintained EDR Killers

## TL;DR

ESET Research (Jakub Soucek, 2026-06-18) published a deep-dive into GentleKiller, the in-house EDR-killing framework maintained by The Gentlemen ransomware-as-a-service gang for distribution to affiliates. The suite comprises at least eight GentleKiller variants plus three third-party EDR killers (HexKiller, ThrottleBlood, HavocKiller) and a Rust-based credential stealer named OxideHarvest. Every variant uses BYOVD — loading a legitimately signed but exploitable kernel driver — to reach ring-0 and terminate 400+ security product processes across 48 vendors. The detection engineering challenge this case is built to address: the Gentlemen operators rotate vulnerable drivers across variants (sometimes within days of a public PoC), so hash-based driver detection fails. The durable detection strategy works at the behavioral layer — driver service creation from non-standard paths, the `GentlemenCollection` staging directory, and security process mass termination — and must fire BEFORE the EDR is killed. A May 2026 internal data leak (16.22 GB, Check Point Research) confirmed operator identity and the centralized EDR-killer distribution model.

## Attribution and confidence

| Attribute | Value |
|-----------|-------|
| Primary cluster | The Gentlemen RaaS (operator alias: hastalamuerte / zeta88) |
| Aliases | Chatty Spider (CrowdStrike analog), formerly Qilin/Embargo/LockBit/Medusa/BlackLock affiliates |
| Attribution confidence | **medium** — operator identity confirmed by Check Point via internal leak (May 2026); individual affiliate activities are low-confidence |
| Vendor/date | ESET Research 2026-06-18; Check Point Research 2026-05-04 (leak); BleepingComputer 2026-06-18 |
| Victimology | Southeast Asia, South America, Western Europe; notably NOT US-centric; target selection by FortiGate misconfiguration not geography; 332 published victims in first 5 months of 2026 |
| Genealogy | Repo Day 1 (2026-04-28_TheGentlemen-SystemBC): same operator family, SystemBC botnet. Day 19 (2026-05-15_EtherRAT-TukTuk-Gentlemen): same operator, EtherRAT+TukTuk toolkit. Day 14 (2026-05-12_Qilin-EDR-Killer-msimg32): different operator (Qilin), but same BYOVD class — detection strategy in H1 hunt extends that case. **GentleKiller EDR-killer framework not previously covered in repo.** |

| Vendor | Report | Overlap indicator |
|--------|--------|-------------------|
| ESET Research | 2026-06-18 Killing me gently | Primary deep-dive; 8 GentleKiller variants + 3rd-party killers + OxideHarvest; IOC table with SHA-1 hashes |
| Check Point Research | 2026-05-04 Thus Spoke the Gentlemen (leaked data) | Internal chats confirming operator-provided EDR killers; zeta88 = hastalamuerte confirmed; 8200+ lines leaked comms |
| Group-IB | 2026 HastLaMuerte/Gentlemen RaaS TTPs | Operator founded by disgruntled ex-Qilin affiliate; 90% affiliate cut confirmed |

## Kill chain — summary table

| Stage | MITRE | Detail |
|-------|-------|--------|
| Initial access | T1190 | FortiGate misconfiguration exploited; Gentlemen select victims by edge-device config (NTLM relay, OWA/M365 creds also used per leaked chats) |
| Staging | T1105 | Affiliate receives GentleKiller package from operators; drops to `GentlemenCollection` directory |
| Driver install | T1543.003 | Vulnerable driver written to %TEMP% or %PROGRAMDATA%; installed as Windows kernel service via sc.exe or SCM API |
| Privilege escalation | T1106 | DeviceIoControl IOCTL to abused driver achieves kernel-level execution |
| Masquerading | T1036, T1036.001 | Binary impersonates legitimate security vendor (filename, version info, icon, copied invalid cert); Enigma/Themida packing applied |
| EDR kill | T1562.001, T1685 | Loop through 400+ security process names; TerminateProcess via kernel handle; EDR callbacks unregistered; telemetry goes dark |
| Credential theft | T1552.001 | OxideHarvest (Rust) harvests Chromium and Gecko browser credentials using supplied host list and thread pool |
| Ransomware | T1486 | Encryptor (Go for Windows/Linux; C for ESXi) deployed post-EDR-kill; double extortion |

![GentleKiller BYOVD kill chain](./kill_chain.svg)

The left lane tracks victim-side detection anchors from initial access through EDR silence; the right lane shows the Gentlemen operator toolkit lifecycle. The key detection windows are highlighted in red (critical stages): driver service install (last moment with full telemetry) and the GentlemenCollection staging directory (durable behavioral anchor). Cross-lane arrows show where defender telemetry is available versus where it is killed.

## Stage-by-stage detail

### Stage 1 — Initial Access (T1190 / T1078)

Gentlemen affiliates gain initial access primarily by exploiting FortiGate misconfiguration. Check Point's analysis of the leaked internal data reveals that operators sort candidate victims by their FortiGate endpoint configuration and assign them to vetted affiliates. NTLM relay attacks and OWA/M365 credential compromise are secondary vectors. The non-US victimology reflects this targeting model: affiliates look for exploitable FortiGate instances globally.

### Stage 2 — Staging via GentlemenCollection (T1105 / T1074.001)

Every Gentlemen intrusion observed by ESET created a staging directory named `GentlemenCollection` before deploying EDR killers. The operator provides affiliates with a pre-packaged toolkit containing all applicable EDR-killer variants. The staging directory name is the most durable behavioral anchor in the entire toolkit — it has appeared consistently since February 2026 across all investigated intrusions regardless of which driver or packer was used.

```
C:\ProgramData\GentlemenCollection\
    Valorant2.exe          # GentleKiller Valorant variant (Themida)
    vgk.sys                # Tower of Fantasy anti-cheat driver (vulnerable)
    Avast.exe              # HexKiller (Gentlemen-wrapped)
    googleApiUtil64.sys    # Baidu BdApi driver (vulnerable)
    buildx641.exe          # OxideHarvest credential stealer
```

### Stage 3 — Driver Service Installation (T1543.003)

Each GentleKiller variant installs its associated vulnerable driver as a Windows kernel service. This occurs via `sc.exe create <name> type= kernel binPath= <driver_path>` or direct calls to `OpenSCManagerW` / `CreateServiceW`. The driver is written from the GentlemenCollection staging directory to a target path (commonly `%TEMP%` or `%PROGRAMDATA%`) before service creation.

```cmd
sc create GentleKillSvc type= kernel binPath= "C:\ProgramData\vgk.sys" start= demand
sc start GentleKillSvc
```

This service creation step is the critical detection window: telemetry is still fully available, and the action is definitively anomalous for a driver landing in `%PROGRAMDATA%`.

### Stage 4 — Privilege Escalation via DeviceIoControl (T1106)

After the driver service starts, GentleKiller calls `DeviceIoControl` with vendor-specific IOCTL codes to reach kernel level. The exact IOCTL differs per variant (each driver exposes different control codes), but the behavior — user-mode process obtaining kernel handles to terminate protected processes — is invariant across all variants. The Qilin case (Day 14) used IOCTL `0x2222008` with `rwdrv.sys`; GentleKiller uses different codes per driver but the same DeviceIoControl call chain.

### Stage 5 — Masquerading and Packing (T1036, T1036.001, T1027)

Gentlemen operators apply a standardized defense-evasion layer to all tools in the suite (including third-party killers they did not develop):
- **Filename impersonation**: `Kasps<suffix>.exe`, `FaceIT<suffix>.exe`, `Valorant<suffix>.exe`, `BitD<suffix>.exe`, `MB<suffix>.exe`, `G11<suffix>.exe` / `Symantec<suffix>.exe`
- **Suffix meaning**: `1` = Enigma-protected; `2` = Themida-protected; `Light` = no packer + fake cert; `Clear` = no packer, no cert
- **Invalid digital signatures**: copied from legitimate vendor binaries (Kaspersky, Valorant, Javelin, etc.) — invalid but visually convincing in Explorer / Windows file properties
- **Version information and icons**: set to match the impersonated vendor

This layer is applied post-compilation to samples the operators did not write (HexKiller, ThrottleBlood, HavocKiller), demonstrating operator-level tradecraft standardization.

### Stage 6 — EDR Kill Loop (T1562.001, T1685)

GentleKiller executes a loop that periodically calls `TerminateProcess` on all processes matching 400+ names across 48 security vendors. The loop runs continuously to prevent restarted security processes from recovering. Key targets include:

- Microsoft Defender: `MsMpEng.exe`, `MsSense.exe`, `SecurityHealthService.exe`, `windefend.exe`
- CrowdStrike Falcon: `CSFalconService.exe`, `CSFalconUI.exe`, `ARWSRVC.EXE`
- SentinelOne: `SentinelAgent.exe`, `SentinelAgentWorker.exe`, `SentinelServiceHost.exe`
- Sophos: `SophosHealth.exe`, `SAVService.exe`, `SophosUI.exe`, `McsAgent.exe` (20+ processes)
- ESET: `ekrn.exe`, `egui.exe`, `ERAAgent.exe`
- Kaspersky: `avp.exe`, `klnagent.exe`, `kavtray.exe` (20+ processes)
- Sysmon: `Sysmon.exe`, `Sysmon64.exe`
- (Full list of 400+ processes in ESET report; subset in iocs.csv notes)

After this loop completes, host telemetry goes dark. No further Sigma/KQL rules fire.

### Stage 7 — OxideHarvest Credential Theft (T1552.001)

OxideHarvest is a Rust-based credential stealer used by Gentlemen affiliate `quant`. It accepts: `-i <hostlist>` (newline-delimited), `-u <user>`, `-p <pass>`, `-t <threads>`, `-o <output>`. It logs into specified hosts and exfiltrates browser credential stores (Chromium-based: Chrome, Edge, Brave, Opera, Vivaldi; Gecko-based: Firefox, Waterfox, PaleMoon). SHA-1: `A5CF917EC4A7DFBDFA43621398604805D860C718` (`buildx641.exe`, VirusTotal confirmed by ESET).

### Stage 8 — Ransomware Deployment (T1486)

Gentlemen operators provide affiliates with a Go-based encryptor targeting Windows and Linux, and a C-based encryptor targeting ESXi. Double extortion: data is exfiltrated before encryption and threatened for publication on the leak site if ransom is not paid. The gang has posted 332 victims in the first 5 months of 2026 (second most active RaaS per Check Point).

## RE notes

| Component | SHA-1 | Lang | Packer | Notes |
|-----------|-------|------|--------|-------|
| GentleKiller Kaspersky variant (Kasps.exe) | 8AE6BD18B129061F63642531F1B684CF0383C75D | C/C++ | Enigma (suffix 1) | Impersonates Kaspersky; drops eb.sys custom rootkit |
| GentleKiller FACEIT variant (FaceIT1.exe) | D605994FC72A2BB59B5CFB1624A1B9170ECA73A2 | C/C++ | Enigma | Abuses NSecsoft nseckrnl.sys |
| GentleKiller Valorant variant (Valorant2.exe) | 5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3 | C/C++ | Themida (suffix 2) | Abuses Tower of Fantasy anti-cheat vgk.sys |
| GentleKiller WatchDog variant (BitD1.exe) | A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62 | C/C++ | Themida | Abuses Zemana dmx.sys |
| GentleKiller G11 variant (Symantec.exe) | D29670E684E40DDC89B47010C37CBC96737035B6 | C/C++ | variable | Abuses PoisonX rootkit G11.sys |
| HavocKiller (Sophos.exe) | F0537CBB773AE12100B36731E7C39F5A9D852B14 | unknown | Gentlemen layer | Third-party; in Gentlemen suite since before Jan 23 2026 |
| OxideHarvest (buildx641.exe) | A5CF917EC4A7DFBDFA43621398604805D860C718 | Rust | variable mimicry | Credential stealer; multi-threaded; -i/-u/-p/-t/-o CLI |

**Shared template across GentleKiller variants**: consistent strings, identical code obfuscation, periodic loop for process termination, same targeting scope. Design allows rapid driver swap without major code changes — Gentlemen weaponized UnknownKiller and PoisonX PoCs within days of public release. The impersonation layer (filename + invalid cert + version info + icon) is applied post-compilation, meaning the operators can wrap any third-party tool without source code.

**OxideHarvest**: Rust binary, unobfuscated JSON config in most builds containing full browser path strings (`chronium_browsers`, `gecko_browsers`). Wraps different packers per deployment but config strings are durable YARA anchors. VirusTotal entry confirmed: `buildx641.exe` = OxideHarvest per ESET.

## Detection strategy

### Telemetry that matters

| Source | Events | Why |
|--------|--------|-----|
| Sysmon EID 6 | RawAccessRead / ImageLoad for `.sys` | Driver loaded into kernel — must alert before EDR kill |
| Windows System EID 7045 | New Service Installed | Kernel driver service created from non-standard path |
| DeviceRegistryEvents | HKLM\SYSTEM\CurrentControlSet\Services ImagePath writes | Service pointing to .sys in %TEMP%/%PROGRAMDATA% |
| DeviceFileEvents | File created/modified in GentlemenCollection path | Staging directory artifact |
| DeviceProcessEvents | ProcessTerminated for security product processes | Post-kill signal; requires threshold aggregation |
| DeviceImageLoadEvents | Low-prevalence .sys from user-writable path | Driver load pre-kill |
| Network: SMB burst from single host | Multiple auth attempts to subnet hosts | OxideHarvest lateral credential harvest |
| XDR console: host heartbeat gap | Zero events for 5+ min from previously-active host | Out-of-band EDR silence detection |

### Detection coverage

| Engine | File | Logic |
|--------|------|-------|
| Sigma | sigma/gentlemen_staging_dir_creation.yml | file_event: TargetFilename contains GentlemenCollection |
| Sigma | sigma/byovd_driver_service_install.yml | process_creation: sc.exe create type= kernel + path not in System32/drivers |
| Sigma | sigma/edr_process_mass_termination.yml | process_creation: taskkill targeting named security processes |
| KQL | kql/gentlemencollection_staging.kql | DeviceFileEvents: FolderPath or FileName has GentlemenCollection |
| KQL | kql/byovd_service_driver_creation.kql | DeviceRegistryEvents: Services ImagePath .sys in user-writable paths |
| KQL | kql/edr_process_termination_chain.kql | DeviceProcessEvents: 3+ security processes terminated within 1 min |
| KQL | kql/oxideharve_credential_harvester.kql | DeviceProcessEvents: buildx641.exe / buildx64.exe or -i -u -p -t -o CLI pattern |
| YARA | yara/gentlekiller_oxideharve.yar | GentleKiller_Process_Termination_Target_List: GentlemenCollection + 3+ process names |
| YARA | yara/gentlekiller_oxideharve.yar | GentleKiller_Impersonation_Layer: Enigma/Themida + vendor name + EDR process names |
| YARA | yara/gentlekiller_oxideharve.yar | OxideHarvest_Rust_Credential_Stealer: Rust panic + chronium_browsers config + browser paths |
| Suricata | suricata/gentlemen_byovd_suite.rules | 6 rules: OxideHarvest SMB burst / HTTP cred exfil / .sys HTTP download / FortiGate recon / SystemBC beacon / OxideHarvest filename |

### Threat hunting hypotheses

- **H1** (`hunts/peak_h1_byovd_pre_kill_window.md`): Correlate kernel driver service creation from non-standard path with subsequent EDR process termination within 10 minutes on same host — the pre-kill window.
- **H2** (`hunts/peak_h2_gentlemencollection_staging.md`): Hunt for `GentlemenCollection` string in file, process, and registry telemetry over 30 days — IOC-agnostic staging artifact.
- **H3** (`hunts/peak_h3_edr_silenced_host.md`): Identify hosts with abrupt telemetry silence (zero process events) while still generating network traffic — out-of-band EDR kill detection.

## Incident response playbook

### First 60 minutes (triage)

1. Alert fires (GentlemenCollection file event, driver service creation, or EDR silence) — identify affected host(s)
2. Query `edr_process_termination_chain.kql` against the host for the last 2 hours
3. Query `byovd_service_driver_creation.kql` — retrieve driver filename and path
4. Hash the driver file: compare SHA-1 to ESET IOC table in `iocs.csv`
5. Query `gentlemencollection_staging.kql` — list all files in the staging directory
6. Check `oxideharve_credential_harvester.kql` for OxideHarvest execution
7. Determine scope: run H2 hunt across ALL hosts for GentlemenCollection presence
8. Escalate to P1 IR if any host shows EDR silence + network activity (H3 hunt result)

### Artifacts to collect

| Artifact | Path | Tool | Why |
|----------|------|------|-----|
| Volatile RAM | Full memory image | WinPmem / Magnet AXIOM | Driver code, IOCTL handles, GentleKiller loop memory |
| GentlemenCollection directory | Variable (often %PROGRAMDATA%) | xcopy / Velociraptor | All EDR-killer binaries and dropped drivers |
| Driver .sys files | %TEMP%, %PROGRAMDATA% | Get-FileHash | Hash comparison to ESET IOC list |
| Service registry entries | HKLM\SYSTEM\CurrentControlSet\Services | reg export | Driver service config |
| $MFT | C:\ root | MFTECmd | Creation timestamps for GentlemenCollection and drivers |
| $UsnJrnl | C:\$Extend\$UsnJrnl | MFTECmd | Driver file creation sequence |
| OxideHarvest output file | Location specified by -o arg | retrieve via admin share | Harvested credentials |
| Browser credential stores | Chrome/Edge/Firefox profile dirs | manual + forensic | Confirm what OxideHarvest targeted |
| Windows Event Log | System 7045, 7036, 7031 | EvtxECmd | Service creation and stop records |

### IR queries and commands

```powershell
# Enumerate kernel services pointing to .sys in user-writable paths
Get-WmiObject Win32_SystemDriver | Where-Object {
    $_.PathName -match 'Temp|ProgramData|Users\\Public|AppData'
} | Select-Object Name, PathName, State, StartMode | Format-List

# Hash all .sys files in suspicious locations
Get-ChildItem -Path "C:\ProgramData\","$env:TEMP" -Recurse -Filter "*.sys" -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA1 | Format-Table Path, Hash

# Check for GentlemenCollection directory
Get-ChildItem -Path "C:\" -Recurse -Directory -Filter "GentlemenCollection" -ErrorAction SilentlyContinue

# List stopped/failed security services (post-kill evidence)
Get-Service | Where-Object { $_.DisplayName -match 'Defender|CrowdStrike|Sentinel|Sophos|ESET|Carbon' } |
    Select-Object Name, Status, DisplayName | Format-Table
```

```bash
# Linux/ESXi scope check (OxideHarvest targets Windows; encryptor targets ESXi)
find /tmp /var/tmp -name "*.bin" -newer /proc -executable 2>/dev/null
ps aux | grep -E 'esxcli|vim-cmd|esxi|encrypt' | grep -v grep
```

### Containment, eradication, recovery

**DO NOT** immediately reboot the affected host — volatile RAM contains the driver's kernel structures and the GentleKiller process memory. Acquire RAM first.

**DO NOT** delete the GentlemenCollection directory before forensic imaging — it contains all staged binaries needed for attribution and hash confirmation.

**Containment steps:**
1. Isolate at network layer (NAC / switch port shutdown / firewall ACL) — do not rely on OS-level isolation after EDR kill
2. Disable the malicious driver service: `sc stop <GentleKillSvc>; sc delete <GentleKillSvc>`
3. Revoke and rotate all credentials accessible from the host (browser credentials via OxideHarvest may be in threat actor hands)
4. Force-rotate FortiGate credentials across all edge devices (initial access vector)
5. Audit all hosts in the `GentlemenCollection` scope via H2 hunt — secondary hosts may be staged but not yet detonated

**Exit criteria for eradication:**
- All GentleKiller driver .sys files removed and registry services deleted
- GentlemenCollection directory removed after forensic imaging
- OxideHarvest output file retrieved and credential rotation completed
- No further anomalous kernel driver service creation events in 24h window

### Recovery validation

```powershell
# Verify security products restarted and reporting
Get-Service -Name WinDefend, Sysmon64 | Select-Object Name, Status
# Confirm Sysmon is generating events (EID 1 within last 5 min)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 | Select-Object TimeCreated, Id

# Verify no residual driver services
Get-WmiObject Win32_SystemDriver | Where-Object {
    $_.PathName -notmatch 'Windows\\System32\\drivers|Windows\\SysWOW64\\drivers|Program Files'
} | Select-Object Name, PathName
```

## IOCs

| Type | Value | Context | Confidence | Source |
|------|-------|---------|------------|--------|
| sha1 | 8AE6BD18B129061F63642531F1B684CF0383C75D | GentleKiller Kaspersky variant (Kasps.exe) | high | ESET 2026-06-18 |
| sha1 | BA914FE77B177B45799403B16DD14765C510A074 | eb.sys custom rootkit (Kaspersky variant) | high | ESET 2026-06-18 |
| sha1 | D605994FC72A2BB59B5CFB1624A1B9170ECA73A2 | GentleKiller FACEIT variant (FaceIT1.exe) | high | ESET 2026-06-18 |
| sha1 | 5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3 | GentleKiller Valorant variant (Valorant2.exe) | high | ESET 2026-06-18 |
| sha1 | A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62 | GentleKiller WatchDog variant (BitD1.exe) | high | ESET 2026-06-18 |
| sha1 | 2F86898528C6CAB3540C486A9BFAA0C029B73950 | GentleKiller Network Blocker variant (MB2.exe) | high | ESET 2026-06-18 |
| sha1 | A19117175DBC9BA4D23B5DCE8415E299A2E32192 | GentleKiller Cleaner variant (Deletor.exe) | high | ESET 2026-06-18 |
| sha1 | D29670E684E40DDC89B47010C37CBC96737035B6 | GentleKiller G11 variant (Symantec.exe) | high | ESET 2026-06-18 |
| sha1 | CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01 | HexKiller (Avast.exe) Gentlemen-wrapped | high | ESET 2026-06-18 |
| sha1 | F0537CBB773AE12100B36731E7C39F5A9D852B14 | HavocKiller (Sophos.exe) Gentlemen-wrapped | high | ESET 2026-06-18 |
| sha1 | 7131B377E96016DC1911020C9F95B1B4D042D7B4 | ThrottleBlood (Sent.exe) Gentlemen-wrapped | high | ESET 2026-06-18 |
| sha1 | A5CF917EC4A7DFBDFA43621398604805D860C718 | OxideHarvest buildx641.exe Rust stealer | high | ESET 2026-06-18 |
| sha1 | 96F0DBF52AED0AFD43E44500116B04B674F7358E | dmx.sys Zemana WatchDog driver (WatchDog variant) | high | ESET 2026-06-18 |
| sha1 | 56BEE9DF5833A637F5C54D5911DF98B0812FE643 | G11.sys PoisonX rootkit (G11 variant) | high | ESET 2026-06-18 |
| string | GentlemenCollection | Staging directory name across all Gentlemen intrusions | high | ESET 2026-06-18 |

Full IOC list in `iocs.csv` (34 entries).

## Secondary findings

- **GentleKiller PoC weaponization speed (#19 RE)**: The Gentlemen operators incorporated UnknownKiller (eb.sys rootkit) and PoisonX driver PoCs within days of their public GitHub disclosure. This cadence — PoC public → weaponized in suite within 2-7 days — means the driver hash blocklist (Microsoft Vulnerable Driver Blocklist) lags active exploitation. The only detection that survives this cycle is behavioral: driver service creation from a non-standard path is anomalous regardless of which driver is used. Defenders who rely on hash-based blocklists will always be behind; defenders who alert on the behavior will not be.

- **Operator EDR-killer distribution model vs. affiliate self-sourcing (#3 Ransomware)**: Most RaaS gangs delegate EDR killing to affiliates. Gentlemen centralize it: operators develop, maintain, and distribute the suite. This inverts the risk model — affiliates gain a ready-made, continuously updated EDR-kill capability without needing technical expertise; operators gain tighter control and consistent tradecraft. The 90% affiliate revenue share is what attracts affiliates despite stricter operational rules. RansomHub took a different path (single EDR killer, EDRKillShifter, developed in-house). Gentlemen's portfolio approach (8+ in-house variants + 3 external) provides redundancy when one driver or PoC is blocked. IR teams should expect all tools in the portfolio to appear in the same intrusion, not just one.

- **OxideHarvest as affiliate-side intelligence tool (#19 RE)**: OxideHarvest is not an operator tool — it was developed by affiliate `quant`. Its purpose is pre-encryption credential harvest from browser stores to enable follow-on access even if the ransom is not paid and the victim rebuilds. The Rust language choice (not typical for Gentlemen operator tools) is the flag. Browser credential theft via OxideHarvest running on a compromised host means that any user who logged into corporate services from that host should have credentials rotated regardless of whether ransomware deployed.

## Pedagogical anchors

- **Hash-based IOC blocking is insufficient for BYOVD suites with driver rotation**: When the threat actor can swap the vulnerable driver within days of a PoC release (as Gentlemen do), a static hash blocklist will always lag active exploitation. The Microsoft Vulnerable Driver Blocklist helps but requires continuous updating and OS-level HVCI/WDAC enforcement. The detection engineering lesson: build behavioral detections for the invariant (driver service creation from non-standard path) not the variant (specific driver hash).
- **The staging directory is the detection gift**: `GentlemenCollection` is the single most actionable IOC in this case — it appears before the EDR kill, is present in all variants, and has zero legitimate use cases. A Sigma rule on a file event for a string with no legitimate use cases is as close to zero false positives as detection engineering gets. When building detections for operator-maintained toolkits, hunt for the logistics artifact (staging path, naming convention) before hunting for the payload.
- **Operator telemetry gap planning**: After GentleKiller kills EDR processes, defender telemetry from the host goes dark. The H3 hunt (EDR-silenced host) detects this absence rather than a presence. Detection engineers must build "absence of expected signal" rules alongside "presence of malicious signal" rules; the latter fail exactly when the attacker wants you blind.
- **Pre-encryption credential theft changes the recovery math**: OxideHarvest harvesting browser credentials before encryption means the attacker retains access to SaaS services, VPNs, and cloud consoles even after the victim pays the ransom and rebuilds. The recovery playbook must include full credential rotation for all users who had sessions on the affected host — not just password reset for the infected machine account.
- **Genealogy-aware detection**: This case builds on the Qilin BYOVD chain (Day 14) and extends the Gentlemen track (Days 1, 19). The H1 hunt's pre-kill-window detection is a direct generalization of the Day 14 rwdrv.sys service detection, now applied to all 8 GentleKiller variants. Maintaining genealogy-aware detections means a single behavioral rule covers the entire BYOVD class rather than requiring per-actor rules.

## What's in this folder

| File | Purpose |
|------|---------|
| [README.md](./README.md) | Full case write-up (15 sections) |
| [kill_chain.svg](./kill_chain.svg) | Two-lane visual (Template A): victim-left EDR-kill stages, operator-right toolkit lifecycle |
| [sigma/gentlemen_staging_dir_creation.yml](./sigma/gentlemen_staging_dir_creation.yml) | file_event: GentlemenCollection directory — highest-fidelity pre-kill alert |
| [sigma/byovd_driver_service_install.yml](./sigma/byovd_driver_service_install.yml) | process_creation: sc.exe kernel driver service from non-standard path |
| [sigma/edr_process_mass_termination.yml](./sigma/edr_process_mass_termination.yml) | process_creation: taskkill targeting security product processes |
| [kql/gentlemencollection_staging.kql](./kql/gentlemencollection_staging.kql) | Defender XDR DeviceFileEvents: staging directory artifact |
| [kql/byovd_service_driver_creation.kql](./kql/byovd_service_driver_creation.kql) | DeviceRegistryEvents: driver service ImagePath in user-writable paths |
| [kql/edr_process_termination_chain.kql](./kql/edr_process_termination_chain.kql) | DeviceProcessEvents: 3+ security processes terminated within 60s |
| [kql/oxideharve_credential_harvester.kql](./kql/oxideharve_credential_harvester.kql) | DeviceProcessEvents: OxideHarvest by filename and CLI pattern |
| [yara/gentlekiller_oxideharve.yar](./yara/gentlekiller_oxideharve.yar) | 3 rules: GentleKiller process list, impersonation layer, OxideHarvest config strings |
| [suricata/gentlemen_byovd_suite.rules](./suricata/gentlemen_byovd_suite.rules) | 6 rules (SIDs 9260001-9260006): OxideHarvest SMB/HTTP, driver download, FortiGate recon, SystemBC, OxideHarvest filename |
| [hunts/peak_h1_byovd_pre_kill_window.md](./hunts/peak_h1_byovd_pre_kill_window.md) | PEAK H1: driver service creation + EDR silence within 10 min on same host |
| [hunts/peak_h2_gentlemencollection_staging.md](./hunts/peak_h2_gentlemencollection_staging.md) | PEAK H2: GentlemenCollection string hunt across file/process/registry telemetry |
| [hunts/peak_h3_edr_silenced_host.md](./hunts/peak_h3_edr_silenced_host.md) | PEAK H3: hosts with telemetry silence but active network — out-of-band EDR kill detection |
| [iocs.csv](./iocs.csv) | 34 entries: SHA-1 hashes for all 8 GentleKiller variants + drivers + HexKiller + ThrottleBlood + HavocKiller + OxideHarvest + behavioral anchors |

## Sources

- [ESET Research: Killing me gently: Inside Gentlemen's EDR killer framework (2026-06-18)](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/)
- [BleepingComputer: Gentlemen ransomware uses multiple EDR killers to disable defenses (2026-06-18)](https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/)
- [Check Point Research: Thus Spoke...The Gentlemen (internal leak analysis)](https://research.checkpoint.com/2026/thus-spoke-the-gentlemen/)
- [Check Point Research: DFIR Report — The Gentlemen](https://research.checkpoint.com/2026/dfir-report-the-gentlemen/)
- [SOCprime: Gentlemen Uses EDR Killers and BYOVD for Evasion](https://socprime.com/active-threats/killing-me-gently-inside-gentlemens-edr-killer-framework/)
- [Infosecurity Magazine: GentleKiller Framework Disables Victims' Security Software](https://www.infosecurity-magazine.com/news/gentlekiller-gentlemen-ransomware/)
- [Group-IB: HastaLaMuerte / Gentlemen RaaS TTPs](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/)
