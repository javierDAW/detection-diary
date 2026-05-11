# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

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
- `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/` — Cleafy Labs technical write-up of a Russian-speaking MaaS Android banking RAT priced at USD 650-720 per month that targets 400+ banking, fintech and cryptocurren