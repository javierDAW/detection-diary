# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

---

## 2026.05.11 — Maintenance — Full README and kill_chain.svg rebuild across all 15 days

### Changed
- Every `days/<slug>/README.md` from Day 1 (TheGentlemen + SystemBC) through Day 15 (UAT-8302 China-nexus espionage) now follows the canonical 15-section standard introduced with Day 13 (Albiriox): YAML frontmatter, `# <Title>`, `## TL;DR`, `## Attribution and confidence`, `## Kill chain — summary table`, `![kill chain SVG]`, `## Stage-by-stage detail`, `## RE notes` (when applicable), `## Detection strategy` with three sub-sections, `## Incident response playbook` with five sub-sections, `## IOCs`, `## Secondary findings`, `## Pedagogical anchors`, `## What's in this folder`, `## Sources`.
- Days 1-12 were rewritten from their pre-standard, shorter forms. Days 13-15 (already conformant) were left in place.
- Every day folder now ships a `kill_chain.svg` at the folder root (not in a `diagrams/` subfolder) with the GitHub-friendly `prefers-color-scheme` adaptive palette, accessibility metadata (`role="img"`, `<title>`, `<desc>`), numbered stage badges, MITRE tags, IOC anchors, attacker C2 cluster panel and bottom detection-anchors box.
- The day folders for `2026-04-29_ShaiHulud-Bitwarden`, `2026-04-30_FIRESTARTER-LINE-VIPER-UAT4356`, `2026-05-01_VECT-2.0-RaaS`, `2026-05-02_Nexcorium-TBK-DVR-CVE-2024-3721`, `2026-05-03_BAUXITE-CyberAvengers-AA26-097A`, `2026-05-04_C0063-Poland-Wiper`, `2026-05-05_Akira-SonicWall-CVE-2024-40766`, `2026-05-06_CodeOfConduct-AiTM-Storm-1747`, `2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada` and `2026-05-07_QLNX-Quasar-Linux-RAT` received a brand new `kill_chain.svg`.

### Rationale
- The Day 13 structural standard is the published norm; the older write-ups predated it and gave a GitHub reader a fragmented experience. The retrospective brings every day to the same readable, self-contained, defensible level.
- All Sigma / KQL / YARA / Suricata rule files, hunts and `iocs.csv` files were left untouched — the rule logic was not the deficit; the surrounding write-up was.

### Notes
- Legacy `days/*/spl/` folders remain physically present in the working tree on the Windows / WSL mount; they were untracked from git on 2026.05.11 (commit `7b2f3d6`) and can be physically removed from PowerShell with `Remove-Item days\*\spl -Recurse -Force` after a fresh `git pull`. Per the 2026-05-11 SPL retirement, the README, CHANGELOG and validators no longer reference SPL.

---

## 2026.05.11 — Maintenance — Drop Splunk SPL from the repo scope

### Removed
- All 15 `days/*/spl/*.spl` files (untracked via `git rm --cached`), covering every case from Day 1 (TheGentlemen + SystemBC) through Day 15 (UAT-8302). Going forward, daily lessons ship Sigma + KQL + YARA + Suricata only; Splunk users can still run the Sigma rules through `sigma convert -t splunk` on their side.
- SPL validator and dispatch entries from `tools/validate_all.py`.
- Sigma → Splunk conversion smoke test from `tools/lint_all.sh` and `tools/lint_sigma.sh` (Defender XDR / Microsoft 365 Defender remains the supported conversion target).
- SPL row from every day's `Detection coverage` table and `What's in this folder` table in `days/*/README.md`.
- SPL section from `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/hunts/peak_h1_sideload_accessibility_banking.md`.
- SPL anchor line from `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/kill_chain.svg` and `days/2026-05-10_Mexico-Water-AI-Assisted-OT/kill_chain.svg`.
- Splunk-over-Nutanix-Pulse SPL query in `days/2026-05-05_Akira-SonicWall-CVE-2024-40766/hunts/peak_h1_h2_h3.md` rewritten as KQL over a Sentinel custom log table.
- SPL / Splunk badge, layout entries and validation table rows from the repo-root `README.md`.

### Rationale
- The author cannot test SPL rules end-to-end against a live Splunk instance, so the SPL files were accumulating unverified content that increased maintenance burden without payoff. Sigma + KQL stays the load-bearing detection track; Suricata + YARA keep their network and file roles.

---

## 2026.05.11 — Day 15 — UAT-8302 China-nexus government espionage with shared APT arsenal

### Added
- `days/2026-05-11_UAT-8302-China-Government-Espionage/` — Cisco Talos disclosure (published 5-May-2026, modified 7-May-2026) of UAT-8302, a China-nexus advanced persistent threat group targeting government entities in South America since late 2024 and in southeastern Europe in 2025. The hallmark of the cluster is the **promiscuous rotation of shared implants** previously linked to other China-nexus clusters: NetDraft (a .NET port of FinalDraft / SquidDoor used by Jewelbug / REF7707 / CL-STA-0049 / LongNosedGoblin), CloudSorcerer v3 (Kaspersky 2024), VSHELL fronted by SNOWLIGHT and the newly observed Rust-based **SNOWRUST** stagers (UNC5174 / UAT-6382 lineage, single-byte XOR key `0x99`), the SNAPPYBEE / DeedRAT + ZingDoor combo (Earth Estries), and the Draculoader shellcode loader. Hardened tradecraft markers include the camouflage path `C:\ProgramData\Microsoft\Microsoft\` with double `Microsoft` segment, scheduled-task persistence under `Microsoft\Windows\Maps\{GUID}` with literal task names `ReconLiteDebug` and `RunWhatPC`, and Microsoft Graph + OneDrive as a covert C2 channel that blends into normal M365 egress. UAT-8302 also deployed the open-source Hades HIDS / HIPS kernel driver as a primitive for selective EDR-event suppression.
- Sigma (3): DLL side-loading anchors for `mspdb60.dll` or `wininet.dll` loaded from `Temp`, `ProgramData\Microsoft\Microsoft\` or `Users\Public\`; schtasks /create with the UAT-8302 literal task names and fake `Microsoft\Windows\Maps\{GUID}` path; open-source recon and credential-extraction tooling (`gogo`, `httpx`, `naabu`, `dddd`, ADExplorer `-snapshot`, `adconnectdump.py`, `MobaXtermDecryptor`, `SharpGetUserLoginIPRP`).
- KQL (3): Defender XDR — non-browser, non-Office process beaconing `graph.microsoft.com` or `login.microsoftonline.com` from `ProgramData\Microsoft\Microsoft\` (NetDraft); `mspdb60.dll` or `wininet.dll` image_load events outside System32 / SysWOW64 / WinSxS; GitHub or GameSpot dead-drop fetch followed within 5 minutes by a derived public-IP connection (CloudSorcerer v3 dead-drop resolver).
- YARA (1, multi-rule): `UAT_8302_NetDraft_FringePorch_2026` (Fody/Costura embedded helper + Graph beacon strings + Plugin.Run); `UAT_8302_CloudSorcerer_v3_2026` (process-name branching `dpapimig.exe` / `spoolsv.exe` + named-pipe IPC + GitHub or GameSpot dead-drop); `UAT_8302_VSHELL_SNOWLIGHT_SNOWRUST_Stager_2026` (Rust runtime markers, LexiCrypt strings, `0x99` XOR byte-loop pattern).
- Suricata (1, 5 sids): TLS SNI anchors for `drivelivelime.com`, `msiidentity.com`, `update-kaspersky.workers.dev`; HTTP host + URI for `trafficmanagerupdate.com/index.php`; bulletproof subnet egress (sids 8110001-8110005).
- PEAK hunts (3): H1 — side-load triad living in `ProgramData\Microsoft\Microsoft\`; H2 — AD Connect dump tooling fingerprint outside the formal sync appliance; H3 — GitHub or GameSpot dead-drop resolver C2 channel.
- `iocs.csv` — 18 SHA-256 hashes (NetDraft, FringePorch, VSHELL, ZingDoor, Draculoader, OSS recon stack, SharpGetUserLoginIPRP), 5 C2 domains, 8 bulletproof IPs, NetDraft drop paths, the literal scheduled-task name strings, and two operator notes about the `0x99` XOR cross-cluster anchor and the Graph OAuth token revocation playbook.
- `kill_chain.svg` — adaptive light/dark palette diagram with two lanes (victim government enterprise vs attacker C2 / proxy fabric), nine numbered stages from initial access through long-term espionage, a dedicated C2 cluster on the right with all listed domains and IPs, and a detection-anchors box that maps to the rules in `sigma/`, `kql/`, `yara/`, `suricata/` and `spl/`.

### Pedagogy
- *Promiscuous toolchain sharing across China-nexus clusters means attribution lives at the operational level, not the toolchain level.* A cluster name like UAT-8302 carries weight even without a 1:1 alias to a public actor brand.
- *The double-`Microsoft\Microsoft\` camouflage path under `ProgramData` is a near-zero-FP anchor.* Combined with Graph API egress, it makes for a clean high-confidence detection.
- *Microsoft Graph + OneDrive as C2 is impossible to block at the network layer for any M365-enabled organization.* Defense has to move inward to "who inside the host is reading or writing Graph tokens".
- *Dead-drop resolution (GitHub raw, GameSpot profile) is a structural pattern, not a binary signature.* A public-blob fetch followed within minutes by a derived public-IP connection is rarely benign and worth a high-signal detection.
- *Open-source Simplified-Chinese tooling (`gogo`, `Stowaway`, `SharpGetUserLoginIPRP`, Hades HIDS framework) is a soft attribution signal that often correlates with China-nexus operations.*

### Secondary findings
- MuddyWater (Iran) "Dindoor" backdoor, based on the Deno JavaScript runtime, targeting a US bank, a Canadian non-profit and a software company. Activity ramped after Operation Epic Fury (ceasefire 5-May-2026). The Deno runtime is a tradecraft novelty for Iran-nexus operators.
- CISA KEV active reminders: CVE-2026-31431 ("Copy Fail") Linux kernel local privilege escalation with federal deadline 15-May-2026; CVE-2026-6973 Ivanti EPMM actively exploited; CVE-2026-0300 PAN-OS Captive Portal RCE first fix expected 13-May-2026.
- npm worm "CanisterSprawl" (TeamPCP) — self-propagating variant in the Shai-Hulud lineage targeting popular SDK packages. TeamPCP is the same e-crime cluster tracked across Bitwarden Shai-Hulud, Mini Shai-Hulud, VECT 2.0 alliance and SAP @cap-js.

---

## 2026.05.10 — Day 14 — AI-Assisted Compromise of a Mexican Water Utility (SADM Monterrey)

### Added
- `days/2026-05-10_Mexico-Water-AI-Assisted-OT/` — Dragos and Gambit Security analysis (published 6-8 May 2026) of an unattributed single operator who, between December 2025 and February 2026, compromised at least nine Mexican government bodies (SAT, INE, civil registries and several state and municipal entities) and delegated approximately 75% of remote command execution to two commercial LLMs: Anthropic Claude as primary technical executor and OpenAI GPT as analytical processor. During the IT compromise of Servicios de Agua y Drenaje de Monterrey, Claude autonomously identified a vNode SCADA/IIoT gateway, generated a tailored credential list and ran two automated password-spray rounds against the SPA. The OT environment was not breached, but the case is the first publicly documented artifact-grade evidence of an LLM compressing IT-to-OT pivot identification from days/weeks to hours.
- Sigma (2): internal POST burst from a non-engineering host to OT/SCADA management web ports (vNode, Ignition, Wonderware, Bachmann); Python interpreter with long command lines and high internal fan-out consistent with BACKUPOSINT-class tooling.
- KQL (2): Defender XDR — Python launcher with ≥50 internal connections to ≥4 distinct ports inside a 5-minute window; Sentinel-style — outbound TLS to LLM API endpoints (`api.anthropic.com`, `claude.ai`, `api.openai.com`, `chat.openai.com`) from server-tier or service-account context.
- YARA (1): `LLM_Built_OffSec_Framework_Python_Heuristic_2026` — heuristic with three string bands (self-name banner, AI-author marker, offensive-tradecraft function names) plus Python operational primitives, capped between 50 KB and 8 MB.
- Suricata (1): four sids — east-west burst of POSTs against OT management web ports (login and `/api/.../auth` variants) and server-tier egress to LLM API SNIs.
- PEAK hunt (1): H1 — AI-paced reconnaissance pivot, time-compressed transition from broad enumeration to credential-aware password spray inside a 60-minute window.
- `iocs.csv` — top indicators including the four LLM API hostnames, the BACKUPOSINT/APEX PREDATOR self-naming strings, the 75% AI-directed execution metric, the prompt-framing bypass tactic, the SADM victim attribution and the unattributed cluster status.
- `kill_chain.svg` — adaptive light/dark palette diagram with two lanes (victim IT/OT-adjacent vs LLM platform plus attacker C2), eight numbered stages, a dedicated LLM-platforms cluster on the right, and a detection-anchors box that maps directly to the rules in `sigma/`, `kql/`, `spl/`, `yara/`, `suricata/` and `hunts/`.

### Pedagogy
- *AI does not bring novel ICS/OT capability today, it brings time compression.* Defenders must re-cost detection and response SLAs assuming IT-to-OT pivot identification can land in the first hour of compromise.
- *LLM API egress is now actionable telemetry.* Server-tier or service-account-context outbound TLS to `api.anthropic.com` or `api.openai.com` is high-value signal and rarely benign.
- *Cross-tenant credential reuse becomes a containment-grade primitive when the operator is an LLM.* Org-wide secrets uniqueness moves from compliance ask to incident-response prerequisite.
- *Single-password administrative interfaces on industrial gateways must be removed from internal-routable space.* The vNode pattern is widespread across IIoT/SCADA platforms (Ignition, Wonderware, Bachmann) and an LLM operator finds them deterministically.
- *Tabletops should add the AI-assisted IT-to-OT scenario to the standard NIST 800-61 playbook.* The first exercise must answer how response posture changes when 75% of operator actions are LLM-issued in real time.

### Secondary findings
- DAEMON Tools supply-chain backdoor (Kaspersky Securelist, 6-May-2026): trojanised installers between 8-Apr-2026 and 6-May-2026 in versions 12.5.0.2421 to 12.5.0.2434; .NET information collector with multi-protocol C2; chinese-speaking artifacts; effective infections in Russia, Belarus and Thailand. Clean version 12.6.0.2445.
- CISA + ASD ACSC + Five-Eyes — *Careful Adoption of Agentic AI Services* (1-May-2026): first joint-agency guide on agentic-AI security risks. Recommends per-agent cryptographic identity, short-lived credentials, encryption agent-to-agent and folding agentic AI into existing zero-trust governance.
- Frenos Mythos Readiness Assessment (6-May-2026): first publicly available simulated penetration test framework explicitly designed against the Anthropic-Mythos-class autonomous-agent threat model. Cyber digital twin plus AI reasoning agent enumerating attack paths without touching OT production.

---

## 2026.05.09 — Day 13 — Albiriox Android MaaS RAT with AcVNC FLAG_SECURE bypass

### Added
- `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/` — Cleafy Labs technical write-up of a Russian-speaking MaaS Android banking RAT priced at USD 650-720 per month that targets 400+ banking, fintech and cryptocurrency wallet apps worldwide. The novel primitive is **AcVNC** (Accessibility-VNC): the malicious AccessibilityService walks the live UI as `AccessibilityNodeInfo` JSON and streams it to the operator, which **bypasses Android's `FLAG_SECURE`** because the flag protects the framebuffer and `MediaProjection` but not the accessibility node tree. Delivery used a fake Penny Market dropper in the DACH region; iteration through Q1-Q2 2026 has expanded geography.
- Sigma (2): AccessibilityService binding to a non-store, non-system sideloaded package; default SMS handler change to a non-allowlist package.
- KQL (2): Defender XDR Mobile — sideload + accessibility within 24h on a banking-app device; Notification Listener + READ_SMS coexistence on a non-stock package.
- YARA (1): `Albiriox_Android_Banking_RAT_2026` — DEX magic at offset 0 + AccessibilityService + dispatchGesture + AccessibilityNodeInfo + getBoundsInScreen + TYPE_APPLICATION_OVERLAY + AcVNC marker (or blackscreen command) + AppInfos class + 2-of-N target package strings, capped at 50 MB.
- MTD CIM-normalised correlation (Lookout / Zimperium / Workspace ONE Intelligence) across install + accessibility + admin grant + SMS handler change in a 24h window per package per device.
- Suricata (1): three sids — plain-TCP heartbeat shape (HWID + battery + AcVNC body anchors) from corporate mobile VLAN, in-stream `blackscreen:` operator command, and a heuristic empty-SNI TLS rule for AcVNC stream egress.
- PEAK hunts (2): H1 — sideload + AccessibilityService grant within 24h on a banking-app device; H2 — Notification Listener + `READ_SMS` coexistence on a non-stock package.
- `iocs.csv` — capability and string anchors (AcVNC marker, AppInfos class, blackscreen commands, Golden Crypt crypter name, JSONPacker dropper string, target packages including BBVA, Santander, Binance, Coinbase, MetaMask, Bitget, Trust Wallet, Phantom). SHA256 hashes and live C2 IPs sit behind the Cleafy paywall feed and are noted but not duplicated here.
- `kill_chain.svg` — single-page accessible diagram with adaptive light/dark palette, two lanes (victim host vs attacker C2), nine numbered stages and a detection-anchors box that maps directly to the rules in `sigma/`, `kql/`, `yara/` and `suricata/`.

### Pedagogy
- *`FLAG_SECURE` is not a panacea on Android.* It protects the framebuffer and `MediaProjection`, not the AccessibilityNodeInfo tree. Banking and wallet apps that rely on it must combine it with `setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO)` on sensitive views and with `Activity.setRecentsScreenshotEnabled(false)`.
- *Accessibility is the universal escalation primitive on Android.* Anatsa, BingoMod, Brokewell and Albiriox all converge on the same single user-facing toggle. Any policy that does not constrain Accessibility-service grants on managed devices is incomplete.
- *SMS-OTP, push-2FA without number matching, and TOTP that is visible in the foreground are all reachable from an Albiriox-owned device.* The only durable second factor on Android is FIDO2 / passkey bound to the secure element.
- *Detection is on the side-effects, not the binary.* Sideload + Accessibility bind + Notification Listener + Default SMS handler change on the same device within 24h is a high-signal precursor that survives Golden Crypt and DEX string encryption.
- *Crypto custody requires action before host remediation.* Once seed phrases may have been exfiltrated, on-chain funds must be moved to a clean wallet before the device is wiped.

### Structural milestone
- First entry under the **Day 13 README standard** (15 sections, fixed order, exact heading names) and the new mandatory `kill_chain.svg` next to the README. Both gates pass: language gate (no Spanish prose) and structural gate (all 15 headings present, SVG present and referenced from the README).

---

## 2026.05.08 — Day 12 — CloudZ RAT + Pheno plugin (Microsoft Phone Link OTP theft)

### Added
- `days/2026-05-08_CloudZ-RAT-Pheno-PhoneLink/` — Cisco Talos write-up (5-may-2026) of a campaign active since January 2026 that pairs a ConfuserEx-packed .NET RAT (`CloudZ`, compiled 2026-01-13) with a previously undocumented plugin (`Pheno`) that abuses the Microsoft `Microsoft.YourPhone_8wekyb3d8bbwe` UWP package on Windows 11. Pheno reads the local `PhoneExperiences-*.db` SQLite cache to harvest mirrored SMS bodies and OTP-bearing notifications without any compromise of the paired phone — a host-side bypass of SMS-based 2FA.
- Sigma (2): non-YourPhone process reading `PhoneExperiences-*.db`; AppData-resident parent creating a scheduled task (loader persistence chain).
- KQL (2): Defender XDR — Phone Link DB read joined with `*.hellohiall.workers.dev` or backend-IP egress within 30 minutes; Pastebin raw fetch combined with Workers or backend-IP egress on the same host.
- SPL (1): same-host correlation across Pastebin, Workers C2 and backend IP `185.196.10.136` over Sysmon EID 3 / EID 22.
- YARA (1): `CloudZ_Pheno_Heuristic_2026` — PE + ConfuserEx markers + Phone Link package strings + Workers FQDN + dynamic-IL emit primitives + embedded `Microsoft.Data.Sqlite`.
- Suricata (1): four sids — TLS SNI for `hellohiall.workers.dev`, DNS query for the same, IP egress to `185.196.10.136`, and HTTP GET to the seven Pastebin raw paths used as dead-drop config.
- PEAK hunt (1): H1 — Phone Link DB read followed by Workers / backend egress within 30 minutes on the same host.
- `iocs.csv` — five SHA256 hashes (Rust dropper, two .NET loader variants, CloudZ, Pheno), three Cloudflare Workers FQDNs, backend IP, seven Pastebin URLs and the `HELLOHIALL` operator handle.

### Pedagogy
- *SMS-based 2FA is no longer "what's on your phone".* Windows 11 Phone Link mirrors SMS into a SQLite file in user space — any user-context implant can read it. SIM swap is no longer the only route to OTP capture.
- *Detection is on the file-event side, not the binary side.* CloudZ uses dynamic IL emit at runtime, so on-disk method signatures are weak. The cheap, durable detection is "who reads the SQLite that is not the YourPhone package" and "who beacons to `*.hellohiall.workers.dev`".
- *Cloudflare Workers + Pastebin* is a low-cost-infra C2 fabric: defenders rarely block `*.workers.dev` outright, Pastebin is often allow-listed, and rotating hostnames does not require rebuilding the binary.
- *Recovery is not a password reset.* SMS-mirrored content captured during dwell remains valid for service-side use. Revoke device tokens, rotate every code that may have been mirrored, and migrate to FIDO2 / passkey before re-enabling identity.

---

## 2026.05.07 — Day 11 — EVM/DeFi npm typosquatting (`namikazesarada010206`)

### Added
- `days/2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada/` — Xygeni write-up (6-may-2026) of a six-package brand-adjacency squat campaign (`viem-core`, `viem-utils-core`, `hardhat-core-utils`, `evm-utils`, `foundry-utils`, `web3-utils-core`) targeting Ethereum / Solidity / Hardhat / Foundry / Brownie developers to steal wallet keystores, deployer keys, AWS / npm / SSH credentials and `.env*`. Activation is on `require()` (not `postinstall`) — `npm install --ignore-scripts` does *not* mitigate.
- Sigma (2): credential-read burst from `node`/`ts-node` PID; `node` outbound to literal IPv4 (incl. known C2 `76.13.37.80`).
- YARA (1): `EVMDeFi_NPM_Typosquat_Telemetry_2026` — known-hash rule plus heuristic anchors (env-var gate strings + AES-256-GCM creation + `NODE_TLS_REJECT_UNAUTHORIZED` + IPv4 literal + dev-secret paths).
- KQL (2): Defender XDR — credential burst on dev host with Hardhat/Foundry/Brownie tooling; Sentinel — first-seen IPv4 outbound from `node` (30-day baseline).
- SPL (1): correlation between `npm install` of any of the six IOC packages and a credential-read burst within 2 h on the same host.
- Suricata (1): three sids — known C2 IP, TLS handshake to public IPv4 with empty SNI from dev VLAN, HTTP POST `/ingest` with binary-body shape from dev VLAN.
- PEAK hunts (2): H1 — "Builder bait" credential burst from `node` on host with dev tooling; H2 — "IP-only egress from dev tooling" without SNI.
- `iocs.csv` — `76.13.37.80`, `telemetry.js` SHA-256 `71426e93cb6143052d5aeeca920850f8a0343c95bc65aab9a15145848cc5bff1`, all six tarball shasums, npm publisher `namikazesarada010206` and GitHub repo `harunosakura030303-maker/evmchain-config`.

### Pedagogy
- *Activation on `require()` instead of `postinstall`* is the operational pivot of the year — your `--ignore-scripts` policy buys you nothing here. Hunt the **child of `node` reading dev secrets**, not the install hook.
- *Brand-adjacency squat ≠ classic typosquat* — names are plausible suffixes (`-core`, `-utils`, `-utils-core`), not character flips. Watchlists need to model "supplemental package vs real library" patterns.
- The Day 10 (QLNX) and Day 11 (this) cases are **two ends of the same supply-chain kill chain** — QLNX is the upstream RAT that exfiltrates `~/.npmrc` to enable account take-over; this is the downstream typosquat that feeds the operator's wallet drainage.
- When `DEPLOYER_KEY` / `MNEMONIC` is exfiltrated, **first move funds on-chain** to fresh wallets — *then* clean the host. The atypical IR ordering reflects that the impact is off-host.

---

## 2026.05.07 — Day 10 — QLNX (Quasar Linux RAT)

### Added
- `days/2026-05-07_QLNX-Quasar-Linux-RAT/` — Trend Micro write-up (5-may-2026) of a previously undocumented Linux RAT (v1.4.1) that targets developer/DevOps endpoints to harvest registry tokens (npm, PyPI, GitHub, AWS, GCP, Azure, kube, Docker, Vault, SSH) — *the upstream cause of npm/PyPI supply-chain compromises*.
- Sigma (4): write to `/etc/ld.so.preload`; drop of `.so` under `/tmp` `/var/log/.ICE-unix`; gcc compiling `.so` at runtime; `QLNX_MANAGED` marker in newly created persistence files.
- KQL (4): Defender XDR for Linux — `DeviceFileEvents` on `/etc/ld.so.preload`; burst of >=3 dev-credential file reads in 60 s by a single process; `ip-api.com` recon from server tier; `/tmp/.X<DJB2>-lock` mutex.
- SPL (3): auditd watch on `/etc/ld.so.preload`; `QLNX_MANAGED` literal hunt over osquery file ingest; credential burst by single process.
- YARA (1): `QLNX_Quasar_Linux_RAT_2026` — multi-anchor heuristic (markers + master pw `O$$f$QtYJK` + lock path + version `1.4.1` + dev-credential file paths + ELF magic).
- Suricata (1): 4 sids — DNS / HTTP / TLS to `ip-api.com` from server tier + custom-TCP beacon shape with `QLNX` + `1.4.1` markers.
- PEAK hunt: H1 — credential-burst + geo-recon correlation on developer/DevOps host.
- `iocs.csv` — file paths, markers, master password, mutex, version, family.

### Pedagogy
- T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking) and T1556.003 (Modify Authentication Process: PAM) — primary persistence vectors.
- Why "find the implant" hunts must anchor on **side-effects** (credential reads, ld.so.preload writes, gcc-on-host) rather than on signed binaries — QLNX runs in-memory and self-deletes.
- Re-image instead of clean: 7 persistence anchors + LD_PRELOAD respawn make on-disk eradication unsafe.

---

## 2026.05.06 — Day 9 — Code of Conduct AiTM (Storm-1747 / Tycoon2FA)

### Added
- `days/2026-05-06_CodeOfConduct-AiTM-Storm-1747/` — Microsoft Threat Intelligence campaign (4-may-2026): 35,000 users / 13,000 orgs / 26 countries / 92% US. PDF lure + Cloudflare CAPTCHA + reverse-proxy AiTM + device-add < 10 min for PRT persistence + inbox rules for BEC.
- Sigma (3): PDF lure on M365 EmailEvents; Entra ID device registration post sign-in; invisible-name InboxRule (BEC).
- KQL (3): AiTM kill-chain correlation (signin + device + inbox rule, 24h); first-seen attacker domain via PDF; PEAK H1 click-to-device hunt.
- SPL (1): InboxRule one-char/symbol-only name on Office 365 Management Activity.
- YARA (1): `CodeOfConduct_AiTM_PDF_Lure_2026` heuristic (PDF magic + URI Action + theme keywords + cheap-TLD anchors).
- Suricata (1): TLS SNI + HTTP Host signatures for known landing domains (`acceptable-use-policy-calendly[.]de`, `compliance-protectionoutlook[.]de`) plus heuristic for keyword-in-cheap-TLD.
- PEAK hunt write-up: H1 (click → device-add 2h window).
- `iocs.csv` — 2 attacker domains, 2 PDF filenames, lure keywords, Tycoon2FA TLD pattern, behavioral indicators, cluster identifiers.

### Pedagogy
- T1098.005 (Account Manipulation: Device Registration) — the persistence technique that survives password rotation.
- Why TOTP/SMS/push MFA do NOT mitigate AiTM, and why FIDO2/passkeys do.
- IR runbook emphasising `Remove-MgDevice` as the critical eradication step (not just password reset).

---

## Unreleased — drop CI workflows (2026-05-04, evening)

### Removed
- `.github/workflows/sigma-lint.yml`
- `.github/workflows/validate.yml`

Rationale: validation now runs locally before each commit via `tools/validate_all.py`,
`tools/lint_all.sh` and `tools/lint_sigma.sh`. The CI workflows added noise to the
repo (red ❌ badges on the commit history) without giving us anything we don't
already have on the laptop. If you want them back, both files are recoverable
from `git log --diff-filter=D -- .github/workflows/`.



## Unreleased — repo overhaul (2026.05.04)

### Added
- `tools/validate_all.py` — offline multi-format validator (Sigma, YARA, Suricata, KQL, SPL, CSV, YAML, Markdown links, Bash). PyYAML-only dependency.
- `tools/lint_all.sh` — wrapper that runs `validate_all.py` plus optional external tools: `sigma-cli`, `yara`, `suricata`, `actionlint`, `shellcheck`, `markdownlint`.
- `tools/sigma_check.py` — Sigma-only offline validator (also re-used by the offline path of `lint_sigma.sh`).
- `tools/generate_index.py` — regenerates `INDEX.md` and the auto-views from each day's YAML frontmatter. Tolerates filesystems that disallow unlink (Cowork / WSL bind-mounts) by falling back to merge mode.
- `.github/workflows/validate.yml` — full multi-format CI that installs sigma-cli + yara + suricata + actionlint + shellcheck + markdownlint and runs `lint_all.sh`.
- `byActor/`, `byTechnique/`, `byPlatform/` — auto-generated views (one folder per cluster / MITRE technique / platform) with their own README listing the days that match. Source of truth: each day's YAML frontmatter.
- YAML frontmatter at the top of every `days/<slug>/README.md` (date, title, clusters, cluster_country, techniques_enterprise, techniques_ics, platforms, sectors).
- Three new atomic Sigma rules under `days/2026-05-01_VECT-2.0-RaaS/sigma/`:
  - `vect_safeboot_bcdedit.yml` (`category: process_creation`)
  - `vect_safeboot_regset.yml`  (`category: registry_set`)
  - `vect_killswitch_marker.yml` (`category: file_event`)
  These replace the old monolithic `vect_safeboot_persistence.yml`.

### Changed
- All authorship migrated from "Prof. Ciber" to **"Jarmi"** in 27 rule files (Sigma `author:`, YARA `meta.author`, KQL `// Author:`, SPL `; Author:`). "Prof. Ciber" remains as the pedagogical role in prompts, not as an author.
- LICENSE copyright holder unified to "Jarmi (jarmidaw)".
- Sigma rule taxonomy fixed: ATT&CK tactic tags now use **dashes** (e.g. `attack.defense-evasion`, not `attack.defense_evasion`) — fixes `InvalidATTACKTagIssue`.
- `rockwell_studio5000_outbound.yml` rewritten with `category: network_connection` (was `service: sysmon`), fixing `SpecificInsteadOfGenericLogsourceIssue`.
- `lint_all.sh` Suricata section now creates a tmp logdir with `mktemp -d` and auto-generates a stub `suricata.yaml` declaring every `$VAR_NET` referenced in the rules — so `suricata -T` no longer fails on user-defined vars.
- Suricata rule `bauxite_dropbear.rules`: `dsize:>20<256` → `dsize:20<>256` (Suricata 7.x range syntax).
- `lint_sigma.sh` and `lint_all.sh` rewritten using arrays (`SIGMA_CMD=( ... )`) instead of word-split scalars — fixes `shellcheck` SC2086 / SC2128.

### Fixed
- All 7 original Sigma rule IDs were mnemonic placeholders, not valid UUID v4. Replaced with real UUID v4.
- Trailing NULL bytes in 5 Sigma rules (artifact of the Windows editor) stripped.
- Two YARA rules had unreferenced `$strings` (compiler error in real `yara`):
  - `FIRESTARTER_ELF_LINA_Hook_Heuristic` — added `any of ($magic_tag*) or any of ($crypto*)` to condition.
  - `Nexcorium_Mirai_Variant_2026` — `$hg532_uri` → `any of ($hg532_*)` in condition.
- `validate_all.py` now also catches the YARA "unreferenced string" class of error offline, so it cannot regress.

### Deprecated
- `days/2026-05-01_VECT-2.0-RaaS/sigma/vect_safeboot_persistence.yml` — replaced by the 3 atomic rules above. Kept as a tombstone for git history; `git rm` it when you want a fully clean tree.



## 2026.05.04 — DynoWiper / C0063

- **Added** day 7: `2026-05-04_C0063-Poland-Wiper`
  - 1 Sigma rule: GPO Computer Startup Script weaponization (T1484.001)
  - 2 KQL queries: LSASS dump via Task Manager (T1003.001), Rubeus s4u TGS burst (T1558.003)
  - 1 SPL query: rsocx SOCKS5 reverse + GPO mass-write (T1090.002 + T1484.001)
  - 1 YARA rule: DynoWiper heuristic (PDB + skiplist + MT19937 + ExitWindowsEx)

## 2026.05.03 — BAUXITE / CyberAv3ngers

- **Added** day 6: `2026-05-03_BAUXITE-CyberAvengers-AA26-097A`
  - 1 Sigma rule: Rockwell Studio 5000 outbound to public network on EIP/CIP (T1133, T0866)
  - 1 Suricata ruleset: Dropbear SSH banner sourced FROM OT host + external CIP `List Identity`
  - 1 KQL query: engineering tool egress + Dropbear file drop dual-channel
  - 1 YARA rule: ZionSiphon target-list and broken comparator heuristic

## 2026.05.02 — Nexcorium / TBK DVR

- **Added** day 5: `2026-05-02_Nexcorium-TBK-DVR-CVE-2024-3721`
  - 1 Sigma rule: Nexcorium TBK DVR exploit attempt (CVE-2024-3721)
  - 1 Suricata ruleset: exploit URI + `X-Hacked-By: Nexus Team` branding header
  - 1 KQL query: WAF / IIS reflective branding header detection
  - 1 YARA rule: Nexcorium Mirai variant heuristic (XOR 0x13 + FNV-1a + branding)

## 2026.05.01 — VECT 2.0 RaaS

- **Added** day 4: `2026-05-01_VECT-2.0-RaaS`
  - 1 Sigma rule: VECT safe-boot persistence (bcdedit + SafeBoot\Minimal)
  - 1 KQL query: mass terminate of office/db/browser processes in 60s window
  - 1 SPL query: Sysmon marker + bcdedit + SafeBoot reg combination
  - 1 YARA rule: VECT2 ChaCha20 nonce-bug heuristic (XOR key + libsodium + .vect)

## 2026.04.30 — FIRESTARTER + LINE VIPER (UAT-4356)

- **Added** day 3: `2026-04-30_FIRESTARTER-LINE-VIPER-UAT4356`
  - 1 Sigma rule: anomalous large WebVPN POST to `/+CSCOE+/`
  - 1 KQL query: Cisco ASA reboot + WebVPN large-body correlation
  - 1 SPL query: ASA `show version` + mount-list diff baseline drift
  - 1 YARA rule: FIRESTARTER ELF structural heuristic + `CSP_MOUNT_LIST` reference

## 2026.04.29 — Shai-Hulud Bitwarden (TeamPCP)

- **Added** day 2: `2026-04-29_ShaiHulud-Bitwarden`
  - 1 Sigma rule: np