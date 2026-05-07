# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

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