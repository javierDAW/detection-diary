---
date: 2026-07-07
title: "KongTuke / Woodgnat: Backdoor.Mistic (MTLBackdoor) — an initial access broker's ClickFix-to-ransomware pipeline"
clusters: ["Woodgnat"]
cluster_country: "Unknown (financially motivated e-crime)"
techniques_enterprise: [T1189, T1566, T1204.004, T1059.001, T1105, T1218.007, T1574.002, T1574.001, T1036.005, T1027, T1620, T1071.001, T1573.001, T1568.002, T1087.002, T1558.003, T1056.002, T1547.001, T1053.005, T1219]
techniques_ics: []
platforms: [windows]
sectors: [insurance, education, technology, professional-services]
category: malware-re
---

# KongTuke / Woodgnat: Backdoor.Mistic (MTLBackdoor) — an initial access broker's ClickFix-to-ransomware pipeline

## TL;DR

Backdoor.Mistic (tracked by Zscaler as MTLBackdoor) is a stealthy new backdoor that Symantec's Threat Hunter Team, Zscaler ThreatLabz and The Hacker News reported on 2026-06-24/25, and that has been deployed in financially motivated intrusions since April 2026 across insurance, education, IT and professional-services organizations. It is assessed with medium confidence to belong to Woodgnat — the initial access broker (IAB) publicly tracked as KongTuke (aka 404 TDS, TAG-124, LandUpdate808, Chaya_002) — because it was dropped alongside the group's Python ModeloRAT, which Symantec has separately watched deliver Qilin ransomware. Woodgnat is a broker: its job is not to encrypt but to build durable, low-visibility access and sell it to ransomware affiliates (Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta). The durable detection story is behavioural — a signed Microsoft binary loading a system-named DLL from a non-System32 path, an interactive PowerShell fetching a remote MSI, and a Run key that impersonates remote-access software while launching portable Python — not any single hash.

## Attribution and confidence

Primary cluster is **Woodgnat** (Symantec naming) = **KongTuke** (public naming), a financially motivated IAB active since at least May 2024. Attribution of Backdoor.Mistic to Woodgnat is **medium** confidence: it is based on Mistic being deployed in the same intrusion as ModeloRAT (a RAT firmly attributed to the group) and on Zscaler's report that Mistic was delivered through a ClickFix chain consistent with Woodgnat tradecraft. The IAB-to-ransomware link (ModeloRAT feeding Qilin) is Symantec Threat Hunter observation; the broader affiliate list (Interlock, Rhysida, Akira, 8Base, Black Basta) is public reporting on Woodgnat.

| Alias / naming | Attributed by | Notes |
|---|---|---|
| Woodgnat | Symantec / Carbon Black | Threat Hunter Team cluster name |
| KongTuke | Public / multiple vendors | Most common public name |
| 404 TDS, TAG-124, LandUpdate808, Chaya_002 | Public / Recorded Future / others | TDS-focused aliases for the same activity |
| MTLBackdoor | Zscaler ThreatLabz | Backdoor tracked as Mistic by Symantec |

**Genealogy with previous repo cases.** KongTuke has appeared once before in this repo only as an *external overlap mention*, not a case: `2026-06-01_GREYVIBE-PhantomRelay-LegionRelay-Ukraine` notes a "PhantomRelayLite reuse … KongTuke ClickFix chain (`obmlink[.]com`)" as an unrelated cybercrime cluster. This is the first repo case anchored on Woodgnat/KongTuke, Backdoor.Mistic/MTLBackdoor and ModeloRAT as primary subjects. The ClickFix delivery technique connects to prior repo cases that used curl-pipe-shell / paste-and-run lures (`2026-05-30_AMOS-OpenClaw-Skill-macOS-Stealer`); the signed-binary DLL side-load tradecraft rhymes with `2026-05-12_Qilin-EDR-Killer-msimg32` and `2026-07-06_ToddyCat-Umbrij-STRD-OAuth-Gmail`, but the malware families and operator are distinct. The downstream ransomware brands (Qilin, Akira) have their own repo cases; here they are only the *buyers* of access, not the intrusion under study.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Lure via compromised WordPress TDS | T1189, T1566 | Woodgnat serves ClickFix / FileFix / CrashFix social-engineering lures |
| Paste-and-run execution | T1204.004, T1059.001 | User pastes a one-liner into Run dialog / Explorer bar / fake Teams IT-support chat |
| Remote MSI staging | T1105, T1218.007 | curl / certutil fetch an MSI; msiexec drops the sideload host + DLLs |
| Signed DLL side-load | T1574.002, T1574.001, T1036.005 | MpExtMs.exe loads version.dll (API hooks) which loads EndpointDlp.dll (Mistic) |
| Mistic in-memory backdoor | T1620, T1071.001, T1573.001 | In-memory tasking, BOF loading, self-delete kill switch |
| Recon + credential theft | T1087.002, T1558.003, T1056.002 | net / AD enum, Kerberoasting, fake lock-screen credential capture |
| Persistence + access handoff | T1547.001, T1053.005, T1219 | ModeloRAT WinPython Run-key masquerade; foothold sold to ransomware affiliate |

![KongTuke/Woodgnat Backdoor.Mistic kill chain](./kill_chain.svg)

The left lane is the victim endpoint and Active Directory path from lure to ransomware handoff; the right lane is Woodgnat's broker infrastructure (WordPress TDS, delivery and C2 domains, ModeloRAT DGA, LOLBin toolset, and the ransomware affiliates who buy the access). Critical (red) nodes are the signed DLL side-load, the in-memory Mistic backdoor, its C2, and the affiliate handoff. The three footer anchors are the detections that survive infrastructure rotation: signed-host/non-system DLL load, explorer-spawned PowerShell fetching an MSI, and a Run-key masquerade launching pythonw.exe.

## Stage-by-stage detail

### Stage 1 — Lure delivered via a compromised-WordPress TDS

Woodgnat operates a traffic distribution system built primarily on compromised WordPress sites, gained through vulnerable/misconfigured plugins, stolen or purchased credentials, and phishing. Injected JavaScript profiles each visitor and serves an evolving series of lures:

```text
ClickFix  (2025)  -> fake error / fake CAPTCHA, paste into the Windows Run dialog
FileFix   (mid-2025) -> paste into the Explorer address bar
CrashFix  (early 2026) -> deliberately crash the browser, "fix" it by running code
```

CrashFix was staged with **NexShield**, a malicious Chrome extension impersonating uBlock Origin Lite distributed via malvertising. Since ~April 2026 the group has also used helpdesk/IT-support pretexts over **external Microsoft Teams chats**, rotating through multiple Microsoft 365 tenants to blunt reactive blocking. **MITRE:** T1189 Drive-by Compromise; T1566 Phishing.

### Stage 2 — Paste-and-run execution

Every lure funnels to the same primitive: the user is convinced to paste an attacker-supplied command and run it. Because it originates from the Run dialog or Explorer address bar, the resulting shell is a child of `explorer.exe`.

```text
parent: explorer.exe  ->  powershell.exe / curl.exe / certutil.exe
```

**MITRE:** T1204.004 User Execution: Malicious Copy and Paste; T1059.001 PowerShell.

### Stage 3 — Remote MSI staged

A multi-stage PowerShell chain (sometimes preceded by a DNS lookup used as a lightweight staging/signalling channel, as Microsoft documented) retrieves an MSI and hands it to msiexec.

```text
hxxp://thomphon[.]com/update.msi        # observed delivery URL
aeff97fe.msi / 48b47c0.msi              # Mistic delivery MSIs (SHA256 in iocs.csv)
```

The MSI drops the signed sideload host (`MpExtMs.exe`), the loader (`version.dll`), the backdoor (`EndpointDlp.dll`), a .NET fake-login stealer (`f.dll`) and a likely privilege-escalation module (`n.dll`). **MITRE:** T1105 Ingress Tool Transfer; T1218.007 Msiexec.

### Stage 4 — Signed DLL side-load (critical)

The legitimate Microsoft binary `MpExtMs.exe` is used to side-load malicious DLLs. The loader `version.dll` hooks two Windows APIs to make the chain robust and stealthy:

```text
GetModuleFileNameW hook -> returns the *legit* path for mpextms.exe (anti-forensic)
LoadLibraryW hook       -> forces the load of the malicious EndpointDlp.dll
```

`EndpointDlp.dll` deliberately borrows a name associated with Microsoft endpoint-DLP tooling so it blends with trusted software. The detection is not the hash but the **shape**: a signed binary loading a system-sounding DLL from a user-writable path. **MITRE:** T1574.002 DLL Side-Loading; T1574.001 DLL Search-Order Hijacking; T1036.005 Masquerading: Match Legitimate Name; T1027 Obfuscated Files or Information.

### Stage 5 — Backdoor.Mistic in memory (critical)

`EndpointDlp.dll` is Backdoor.Mistic. It runs remote payloads directly in memory and exposes typical backdoor verbs plus two operator-favourite features:

```text
upload/download, move/rename/delete, create folder, change poll interval,
execute C2 code in memory (no disk artifact),
load Beacon Object Files (BOFs) to expand capability on demand,
terminate-and-delete (kill switch)
```

In-memory execution plus a self-delete kill switch are consistent with an operator seeking long-term, low-visibility access — exactly what an IAB needs to preserve a saleable foothold. **MITRE:** T1620 Reflective Code Loading; T1071.001 Application Layer Protocol: Web; T1573.001 Encrypted Channel: Symmetric Cryptography.

### Stage 6 — Reconnaissance and credential theft

Post-foothold, the operator enumerates the domain and harvests credentials using built-in tooling and the dropped .NET stealer:

```text
net.exe / PowerShell -> users, groups, computers, sessions, host/service inventory
AD + Kerberoasting queries against accounts with SPNs (crackable creds)
f.dll -> fake lock-screen / login prompt captures credentials
reg.exe, wmic, certutil, finger.exe -> staging and dual-use support
```

**MITRE:** T1087.002 Account Discovery: Domain Account; T1558.003 Kerberoasting; T1056.002 Input Capture: GUI Input Capture.

### Stage 7 — Persistence and access handoff (critical)

Durable access is established with ModeloRAT, delivered as a portable WinPython package (`WPy64-31401`) and run via signed `pythonw.exe`. Persistence uses redundant mechanisms, most notably an HKCU Run key whose *name* impersonates remote-access software:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  value name: AnyDesk | Splashtop | Comms   (masquerade)
  value data: ...\pythonw.exe  (portable WinPython launching ModeloRAT)
```

ModeloRAT uses RC4-encrypted C2 with multiple failover paths; non-domain-joined hosts receive a more heavily obfuscated variant with a **domain-generation algorithm** that cycles fresh C2 domains weekly, while domain-joined enterprise hosts get the higher-value payload. The broker then sells the access; Symantec observed ModeloRAT footholds culminating in Qilin ransomware. **MITRE:** T1547.001 Registry Run Keys; T1053.005 Scheduled Task; T1219 Remote Access Software; T1568.002 Dynamic Resolution: DGA.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| version.dll (loader) | 59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712 | C/C++ | n/a | Hooks GetModuleFileNameW + LoadLibraryW to sideload Mistic |
| EndpointDlp.dll (Mistic) | 1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984 | C/C++ | n/a | In-memory tasking + BOF loading + self-delete kill switch |
| EndpointDlp.dll (Mistic) | afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c | C/C++ | n/a | Additional Mistic sample |
| f.dll (fake lock screen) | 34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc | .NET | n/a | Renders fake login to capture credentials |
| n.dll (priv-esc) | 8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235 | unk | n/a | Likely privilege escalation (per Symantec) |
| aeff97fe.msi (delivery) | 3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be | MSI | n/a | Mistic delivery package |

Two anti-analysis notes stand out. First, the `GetModuleFileNameW` hook is an anti-forensic measure: it makes the abused `MpExtMs.exe` report its legitimate path even when running from a staging directory, defeating naive path checks. Second, Mistic's BOF loading means capability is not statically present in the DLL — like a C2 agent, functionality arrives at runtime, so a pure static triage understates the threat. The self-delete kill switch argues for early memory acquisition before containment.

## Detection strategy

### Telemetry that matters

- **Sysmon:** EID 7 (image load, with signature status) for the MpExtMs.exe -> version.dll/EndpointDlp.dll sideload; EID 1 (process create) for explorer-spawned PowerShell/curl/certutil and pythonw.exe lineage; EID 13 (registry set) for RunMRU and Run-key masquerade; EID 22 (DNS) for DGA beacons.
- **Defender XDR:** `DeviceImageLoadEvents`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`.
- **Network:** DNS + TLS SNI for delivery/C2 domains; HTTP for the `update.msi` GET.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/01_mpextms_sideload_nonsystem_dll.yml | MpExtMs.exe loading version.dll/EndpointDlp.dll from a non-System32 path |
| Sigma | sigma/02_clickfix_rundialog_powershell_msi.yml | explorer.exe-spawned PowerShell/curl/certutil fetching a remote .msi |
| Sigma | sigma/03_modelorat_runkey_masquerade.yml | HKCU Run key named AnyDesk/Splashtop/Comms pointing at portable pythonw.exe |
| KQL | kql/mistic_sideload_endpointdlp_nonsystem.kql | Defender XDR image-load variant of the sideload analytic |
| KQL | kql/clickfix_rundialog_powershell_msi.kql | Defender XDR ClickFix paste-and-run to MSI |
| KQL | kql/modelorat_winpython_persistence.kql | ModeloRAT WinPython Run-key persistence |
| KQL | kql/mistic_woodgnat_c2_network.kql | Callback to known Mistic/Woodgnat C2 + delivery infra |
| YARA | yara/mistic_woodgnat.yar | Loader API-hook + Mistic + fake-lockscreen stealer, behaviour-anchored |
| Suricata | suricata/kongtuke_mistic.rules | DNS/TLS/HTTP/IP anchors for delivery + C2 (9 sids) |

### Threat hunting hypotheses

- **H1 — ClickFix paste-and-run to remote MSI** (`hunts/peak_h1_clickfix_rundialog_to_msi.md`): interactive explorer.exe -> shell tool with http(s) + .msi, then msiexec, corroborated by RunMRU.
- **H2 — Signed binary loading a system-named DLL from a non-system path** (`hunts/peak_h2_signed_binary_nonsystem_sideload.md`): generalises beyond the two filenames to the whole sideload class.
- **H3 — ModeloRAT WinPython persistence + DGA beacon** (`hunts/peak_h3_modelorat_winpython_dga_beacon.md`): Run-key masquerade launching pythonw.exe with high-entropy outbound domains.

## Incident response playbook

### First 60 minutes (triage)

1. Isolate the host at the network layer but **do not kill processes yet** — Mistic runs in memory and self-deletes; you want a memory image first.
2. Capture RAM (and the pagefile) before containment to preserve the in-memory backdoor and any loaded BOFs.
3. Pull `DeviceImageLoadEvents`/EID 7 for `MpExtMs.exe` loading `version.dll`/`EndpointDlp.dll`; confirm the non-System32 path.
4. Recover the pasted command from `HKCU\...\Explorer\RunMRU` to confirm ClickFix and identify the lure domain.
5. Enumerate persistence: HKCU Run keys named AnyDesk/Splashtop/Comms, Startup shortcuts, VBScript launchers, scheduled tasks.
6. Assume credential theft occurred (fake login + Kerberoasting) — begin the credential-reset track in parallel.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Memory image | physical RAM | WinPMEM / Velociraptor | Mistic is in-memory + self-deleting |
| Sideload set | %TEMP% / %APPDATA% / profile | EZ Tools / triage | MpExtMs.exe, version.dll, EndpointDlp.dll, f.dll, n.dll |
| RunMRU | HKCU\...\Explorer\RunMRU | reg / RECmd | Verbatim ClickFix command + lure host |
| Run keys | HKCU\...\CurrentVersion\Run | reg / RECmd | ModeloRAT masquerade persistence |
| Delivery MSI | download path / cache | hash + inspect | aeff97fe.msi / 48b47c0.msi payload set |
| DNS + proxy logs | network | SIEM | C2/DGA beacons, update.msi GET |

### IR queries and commands

```powershell
# Run-key masquerade launching portable Python (ModeloRAT)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
  Format-List AnyDesk,Splashtop,Comms

# Recover the pasted ClickFix command
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

# Find MpExtMs.exe running from a non-Defender path
Get-CimInstance Win32_Process -Filter "Name='MpExtMs.exe'" |
  Select-Object ProcessId,ExecutablePath,CommandLine
```

```bash
# Triage a suspected sideload DLL for the API hooks (offline, safe)
strings -a version.dll | grep -Ei 'GetModuleFileNameW|LoadLibraryW|EndpointDlp'
```

```kql
// Confirm the sideload chain in Defender XDR
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "MpExtMs.exe"
| where FileName in~ ("version.dll","EndpointDlp.dll")
| where FolderPath !has @"\Windows\System32\"
```

### Containment, eradication, recovery

- **Containment exit criteria:** memory captured; host isolated; C2 domains/IPs sinkholed or blocked at egress; RunMRU/Run-key persistence identified.
- **Eradication:** remove the sideload set and all persistence (Run keys, Startup shortcuts, VBScript, scheduled tasks); rotate every credential exposed to the fake-login and Kerberoast (treat domain accounts with SPNs as compromised).
- **What NOT to do:** do not simply delete files and re-image without a memory image (you lose the in-memory backdoor and BOFs); do not assume a password reset alone is sufficient — Kerberoastable service accounts and any tickets must be rotated; do not treat blocking today's C2 as eradication — ModeloRAT rotates via DGA.
- **Recovery:** because Woodgnat sells access, treat a confirmed Mistic/ModeloRAT foothold as a **pre-ransomware** event; hunt for the buyer's staging (new admin accounts, RMM installs, backup tampering) and validate that no affiliate handoff already occurred.

### Recovery validation

Confirm no MpExtMs.exe sideload recurs; no Run key relaunches pythonw.exe; no beacons to known or DGA-shaped C2; Kerberoastable SPNs rotated; and monitoring is in place for a 30-day window given the typical IAB-to-ransomware lead time.

## IOCs

Top indicators (full list in `iocs.csv`):

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | 1e41c7bf…f9d1984 | Backdoor.Mistic (EndpointDlp.dll) | high | Symantec (2026-06-24) |
| sha256 | 59e3c4cb…5520712 | Mistic loader (version.dll, API hooks) | high | Symantec (2026-06-24) |
| sha256 | 34d798a6…0ac07bc | Fake lock-screen stealer (f.dll, .NET) | high | Symantec (2026-06-24) |
| sha256 | 3f797a63…2bbb4be | Mistic delivery MSI (aeff97fe.msi) | high | Symantec (2026-06-24) |
| url | hxxp://thomphon[.]com/update.msi | Mistic MSI delivery URL | high | Symantec (2026-06-24) |
| domain | authorized-logins[.]net | Mistic C2 (mail/php/sss subdomains) | high | Symantec (2026-06-24) |
| domain | updater-worelos[.]com | Mistic C2 (mails/defs subdomains) | high | Symantec (2026-06-24) |
| domain | upd-domain-goloro[.]com | Mistic C2 (mailes/ftps subdomains) | high | Symantec (2026-06-24) |
| ipv4 | 142.93.242.144 | Mistic/Woodgnat network indicator | high | Symantec (2026-06-24) |
| domain | b6w9m2z5x8q1v3k[.]top | ModeloRAT DGA C2 candidate | medium | Symantec (2026-06-24) |
| regkey | HKCU\…\CurrentVersion\Run | ModeloRAT masquerade persistence | high | Symantec (2026-06-24) |
| string | EndpointDlp.dll | Mistic DLL masquerading as MS endpoint-DLP | high | Symantec (2026-06-24) |

**CISA KEV:** this intrusion set abuses ClickFix social engineering and DLL side-loading rather than a specific CVE, so there is no CVE to cross-reference and no `kev.md` is generated for this case. Absence from KEV is expected here and does not imply low severity — an IAB foothold is a direct precursor to ransomware. **Indicator decay:** the C2/delivery IPs and domains are from 2026-06 reporting and rotate (some via DGA); re-validate before blocking in production.

## Secondary findings

- **The broker, not the payload, is the durable target.** Woodgnat sells access to at least six ransomware operations (Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta). Defending against "Qilin" or "Akira" by brand misses the point — the same intrusion could end in any of them. Detect and evict the IAB foothold and you cut off multiple ransomware families at once.
- **Custom tooling is spreading in the e-crime supply chain.** Historically ransomware actors preferred living-off-the-land and dual-use tools; a broker shipping a bespoke in-memory backdoor (Mistic) *and* a bespoke Python RAT (ModeloRAT) signals rising development capability and a group worth tracking as it widens its buyer pool.
- **Social engineering is the whole initial-access story.** ClickFix/FileFix/CrashFix and fake-IT-support Teams chats all reduce to "convince a human to paste and run a command." User-execution telemetry (interactive-parent PowerShell) and paste-source forensics (RunMRU) are disproportionately valuable against this class.

## Pedagogical anchors

- **Hunt the shape, not the hash.** A signed binary loading a system-named DLL from a user-writable path is a portable, hash-independent tell for the entire side-load class — Mistic today, something else next month.
- **In-memory + kill switch changes IR order.** When a backdoor lives in memory and can self-delete, capture RAM *before* you isolate or kill; file scans alone will miss it (Symantec's own warning).
- **An IAB foothold is a pre-ransomware event.** Median IAB-to-ransomware handoff times are short; treat a confirmed Mistic/ModeloRAT infection as the start of an incident, not the end, and hunt for the buyer.
- **Masquerade lives in the name, not the binary.** `EndpointDlp.dll` (endpoint-DLP tooling) and a Run key named "AnyDesk" both weaponise *naming* trust; validate path + signer + data, never the label.
- **Password reset is not eradication.** Kerberoastable SPNs and existing tickets survive a reset; rotate service-account credentials and assume harvested creds are already in the broker's hands.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (template A, malware-re accent). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | Full indicator list (hashes, C2/delivery infra, strings, notes). | [iocs.csv](./iocs.csv) |
| sigma/01_mpextms_sideload_nonsystem_dll.yml | Signed-host non-system DLL side-load. | [file](./sigma/01_mpextms_sideload_nonsystem_dll.yml) |
| sigma/02_clickfix_rundialog_powershell_msi.yml | ClickFix paste-and-run to remote MSI. | [file](./sigma/02_clickfix_rundialog_powershell_msi.yml) |
| sigma/03_modelorat_runkey_masquerade.yml | ModeloRAT Run-key masquerade. | [file](./sigma/03_modelorat_runkey_masquerade.yml) |
| kql/mistic_sideload_endpointdlp_nonsystem.kql | XDR sideload analytic. | [file](./kql/mistic_sideload_endpointdlp_nonsystem.kql) |
| kql/clickfix_rundialog_powershell_msi.kql | XDR ClickFix-to-MSI analytic. | [file](./kql/clickfix_rundialog_powershell_msi.kql) |
| kql/modelorat_winpython_persistence.kql | XDR ModeloRAT persistence analytic. | [file](./kql/modelorat_winpython_persistence.kql) |
| kql/mistic_woodgnat_c2_network.kql | XDR C2/delivery callback analytic. | [file](./kql/mistic_woodgnat_c2_network.kql) |
| yara/mistic_woodgnat.yar | Behaviour-anchored YARA (3 rules). | [file](./yara/mistic_woodgnat.yar) |
| suricata/kongtuke_mistic.rules | Network anchors for delivery + C2 (9 sids). | [file](./suricata/kongtuke_mistic.rules) |
| hunts/peak_h1_clickfix_rundialog_to_msi.md | PEAK hunt: ClickFix to MSI. | [file](./hunts/peak_h1_clickfix_rundialog_to_msi.md) |
| hunts/peak_h2_signed_binary_nonsystem_sideload.md | PEAK hunt: signed-host sideload. | [file](./hunts/peak_h2_signed_binary_nonsystem_sideload.md) |
| hunts/peak_h3_modelorat_winpython_dga_beacon.md | PEAK hunt: ModeloRAT persistence + DGA. | [file](./hunts/peak_h3_modelorat_winpython_dga_beacon.md) |

## Sources

- [Backdoor.Mistic: New Backdoor May be Linked to Ransomware Access Broker (Symantec Threat Hunter Team, 2026-06-24)](https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat)
- [New Mistic Backdoor Linked to KongTuke in ClickFix and ModeloRAT Campaigns (The Hacker News, 2026-06-25)](https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html)
- [Stealthy Mistic backdoor linked to ransomware access broker KongTuke (BleepingComputer, 2026-06-25)](https://www.bleepingcomputer.com/news/security/stealthy-mistic-backdoor-linked-to-ransomware-access-broker-kongtuke/)
- [Self-destructing Mistic backdoor linked to access broker selling corporate footholds to ransomware gangs (The Register, 2026-06-25)](https://www.theregister.com/security/2026/06/25/self-destructing-mistic-backdoor-linked-to-access-broker-selling-corporate-footholds-to-ransomware-gangs/5262579)
- [IT Support: Dissecting the ModeloRAT campaign via Microsoft Teams compromise (Rapid7)](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise/)
- [Inside Mistic, the New Stealth Backdoor in Ransomware Intrusions (Security Affairs, 2026-06)](https://securityaffairs.com/194207/cyber-crime/inside-mistic-the-new-stealth-backdoor-in-ransomware-intrusions.html)
