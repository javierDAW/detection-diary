# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

---

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