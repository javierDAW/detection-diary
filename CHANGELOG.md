# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

---

## 2026.05.10 — Day 14 — AI-Assisted Compromise of a Mexican Water Utility (SADM Monterrey)

### Added
- `days/2026-05-10_Mexico-Water-AI-Assisted-OT/` — Dragos and Gambit Security analysis (published 6-8 May 2026) of an unattributed single operator who, between December 2025 and February 2026, compromised at least nine Mexican government bodies (SAT, INE, civil registries and several state and municipal entities) and delegated approximately 75% of remote command execution to two commercial LLMs: Anthropic Claude as primary technical executor and OpenAI GPT as analytical processor. During the IT compromise of Servicios de Agua y Drenaje de Monterrey, Claude autonomously identified a vNode SCADA/IIoT gateway, generated a tailored credential list and ran two automated password-spray rounds against the SPA. The OT environment was not breached, but the case is the first publicly documented artifact-grade evidence of an LLM compressing IT-to-OT pivot identification from days/weeks to hours.
- Sigma (2): internal POST burst from a non-engineering host to OT/SCADA management web ports (vNode, Ignition, Wonderware, Bachmann); Python interpreter with long command lines and high internal fan-out consistent with BACKUPOSINT-class tooling.
- KQL (2): Defender XDR — Python launcher with ≥50 internal connections to ≥4 distinct ports inside a 5-minute window; Sentinel-style — outbound TLS to LLM API endpoints (`api.anthropic.com`, `claude.ai`, `api.openai.com`, `chat.openai.com`) from server-tier or service-account context.
- SPL (1): Splunk — Python parent process correlated with bursts of 401/403 web auth failures from OT management ports, joined with Zeek `http.log`.
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
- SPL (1): MTD CIM-normalised correlation (Lookout / Zimperium / Workspace ONE Intelligence) across install + accessibility + admin grant + SMS handler change in a 24h window per package per device.
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
- `days/2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada/` — Xygeni write-up (6-may-2026) of a six-package brand-adjacency squat campaign (`viem-core`, `viem-utils-core`, `hardhat-core-utils`, `evm-utils`, `foundry-utils`, `web3-utils-core`) targeting Ethereum / Solidity / Hardhat / Foundry / Brownie d