# detection-diary

> Daily detection content — Sigma, KQL and YARA — derived from real-world threat intel write-ups. One case per day, MITRE ATT&CK mapped, sources cited.

[![Sigma](https://img.shields.io/badge/Sigma-rules-blue)](https://github.com/SigmaHQ/sigma)
[![KQL](https://img.shields.io/badge/KQL-Sentinel%20%7C%20Defender%20XDR-0078D4)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![YARA](https://img.shields.io/badge/YARA-rules-yellow)](https://yara.readthedocs.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Gallery

<!-- AUTOGEN:GALLERY:START -->
**39 cases** · **98 actors/clusters** · **263 ATT&CK techniques** · **15 platforms** · **61 sectors** · 2026-04-29 -> 2026-06-06

> Visual gallery (filterable, light/dark): **[open the Pages site](./docs/index.html)** · full list in **[INDEX.md](INDEX.md)** · facets: [actor](byActor/) · [technique](byTechnique/) · [platform](byPlatform/)

<table>
<tr>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-06_OCPP-EVCharging-ABB-TerraAC-CVE-2025-5517/"><img src="days/2026/06/2026-06-06_OCPP-EVCharging-ABB-TerraAC-CVE-2025-5517/kill_chain.svg" alt="2026-06-06 kill chain" width="240"></a><br><sub><b>2026-06-06</b><br>Opportunistic OCPP / EV-charging exploitation (unattributed)</sub></td>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-05_Netlogon-CVE-2026-41089-DC-RCE/"><img src="days/2026/06/2026-06-05_Netlogon-CVE-2026-41089-DC-RCE/kill_chain.svg" alt="2026-06-05 kill chain" width="240"></a><br><sub><b>2026-06-05</b><br>Opportunistic Netlogon mass-exploitation (unattributed)</sub></td>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-04_Kirki-CVE-2026-8206-WP-AccountTakeover/"><img src="days/2026/06/2026-06-04_Kirki-CVE-2026-8206-WP-AccountTakeover/kill_chain.svg" alt="2026-06-04 kill chain" width="240"></a><br><sub><b>2026-06-04</b><br>Opportunistic WordPress mass-exploitation (unattributed)</sub></td>
</tr>
<tr>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-03_ip6arpa-Reverse-DNS-Phishing/"><img src="days/2026/06/2026-06-03_ip6arpa-Reverse-DNS-Phishing/kill_chain.svg" alt="2026-06-03 kill chain" width="240"></a><br><sub><b>2026-06-03</b><br>Unattributed ip6.arpa Reverse-DNS Phishing Operator (Infoblox-tracked)</sub></td>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-02_Aur0ra-NoRename-InPlace-Ransomware/"><img src="days/2026/06/2026-06-02_Aur0ra-NoRename-InPlace-Ransomware/kill_chain.svg" alt="2026-06-02 kill chain" width="240"></a><br><sub><b>2026-06-02</b><br>Aur0ra (unattributed ransomware family)</sub></td>
<td align="center" valign="top" width="33%"><a href="days/2026/06/2026-06-01_GREYVIBE-PhantomRelay-LegionRelay-Ukraine/"><img src="days/2026/06/2026-06-01_GREYVIBE-PhantomRelay-LegionRelay-Ukraine/kill_chain.svg" alt="2026-06-01 kill chain" width="240"></a><br><sub><b>2026-06-01</b><br>GREYVIBE</sub></td>
</tr>
</table>
<!-- AUTOGEN:GALLERY:END -->

---

## What this is

This repository is my personal **detection journal**. Every day I pick one high-impact, technically meaty case from the threat-intel feed (vendor write-ups from Mandiant, Microsoft, Volexity, Unit 42, ESET, Talos, Securelist, SentinelOne, CrowdStrike, Dragos, plus DFIR Report and CISA advisories) and translate it into **deployable detection content**:

- **Sigma** rules — vendor-agnostic, convertible via `pySigma` / `uncoder` / `sigmac`.
- **KQL** queries — Microsoft Sentinel and Defender XDR.
- **YARA** rules — file and process memory.
- **Suricata / Snort** signatures — when network surface is relevant.
- **PEAK / TaHiTI hunting hypotheses** — with baselines and discriminating signals.

Each entry is grounded on a published, sourced case, so it stays defensible and reproducible.

---

## What this is **not**

- Not a feed for production blocklists. Validate every IOC before wiring it into preventive controls — confidence levels are documented, but circumstances change.
- Not a SigmaHQ replacement. Upstream-quality rules go to [SigmaHQ](https://github.com/SigmaHQ/sigma) via PR; this is the **lab notebook** that precedes that step.
- Not weaponised PoCs. All offensive snippets here are publicly documented and live for **detection design**, not exploitation.

---

## Repository layout

```
detection-diary/
├── README.md               ← landing page; gallery block is AUTO-GENERATED
├── INDEX.md                ← AUTO-GENERATED — gallery + chronological-by-month + facet links
├── CHANGELOG.md
├── LICENSE
├── .gitignore
│
├── days/                   ← source of truth — sharded by year/month
│   └── YYYY/
│       └── MM/
│           └── YYYY-MM-DD_<slug>/
│               ├── README.md       ← YAML frontmatter + the 15-section write-up
│               ├── kill_chain.svg  ← adaptive light/dark kill-chain diagram (mandatory since Day 13)
│               ├── sigma/*.yml
│               ├── kql/*.kql
│               ├── yara/*.yar
│               ├── suricata/*.rules
│               ├── hunts/*.md
│               └── iocs.csv
│
├── docs/                   ← AUTO-GENERATED GitHub Pages gallery (Settings -> Pages -> /docs)
│   ├── index.html          ← self-contained filterable gallery, light/dark
│   ├── data.json           ← one record per case (from frontmatter)
│   └── thumbs/*.svg         ← kill-chain thumbnails
│
├── byActor/                ← AUTO-GENERATED view: one folder per cluster / alias
├── byTechnique/            ← AUTO-GENERATED view: one folder per MITRE ATT&CK ID
├── byPlatform/             ← AUTO-GENERATED view: one folder per platform tag
│
└── tools/
    ├── validate_all.py     ← offline multi-format validator (recursive days/**)
    ├── sigma_check.py      ← Sigma-only offline validator
    ├── lint_sigma.sh       ← Sigma wrapper
    ├── lint_all.sh         ← full chain wrapper
    ├── generate_index.py   ← rebuilds INDEX.md (+ README gallery block) + byActor/ + byTechnique/ + byPlatform/
    └── generate_site.py    ← rebuilds the docs/ Pages gallery
```

> The day folders are **sharded by year/month** so the tree stays browsable and the
> tooling stays fast as the journal grows — but the layout is cosmetic: every link is
> computed from the file location and the chronology comes from each case's `date:`
> field, not its path. `INDEX.md`, the README gallery block, `byActor/`, `byTechnique/`,
> `byPlatform/` and everything under `docs/` are **auto-generated** from the YAML
> frontmatter at the top of each day's `README.md`. To rebuild after adding or editing a day:
>
> ```bash
> python3 tools/generate_index.py   # INDEX.md + README gallery + by* facet views
> python3 tools/generate_site.py    # docs/ Pages gallery (index.html + data.json + thumbs)
> ```
>
> Do not edit the generated files by hand — your changes will be wiped on the next regen.

---

## Naming convention

```
days/YYYY/MM/YYYY-MM-DD_<short-slug>/
```

- `YYYY-MM-DD` is the date the **class was delivered**, not the date the case was disclosed.
- `<short-slug>` is the campaign ID, malware family or actor (kebab-case). Examples:
  - `2026-05-11_UAT-8302-China-Government-Espionage`
  - `2026-05-04_C0063-Poland-Wiper`
  - `2026-05-03_BAUXITE-CyberAvengers-AA26-097A`

---

## The 15-section per-day README standard

Every `days/<slug>/README.md` follows the same 15 canonical sections, in this exact order, with exact heading names. A reader landing on GitHub without any chat context must be able to understand the attack, the TTPs, the detections and the incident response from that one file alone.

1. Frontmatter YAML (`date`, `title`, `clusters`, `cluster_country`, `techniques_enterprise`, `techniques_ics`, `platforms`, `sectors`).
2. `# <Title>` — main heading from the frontmatter.
3. `## TL;DR` — 3–5 sentences: what happened, who, when, victim sector, dwell time, why it matters.
4. `## Attribution and confidence` — cluster + aliases + explicit `high` / `medium` / `low` confidence.
5. `## Kill chain — summary table` — `Stage | MITRE | Detail` rows.
6. An embedded `kill_chain.svg` reference — mandatory adaptive light/dark diagram. Each day uses the relative path inside its own folder; an example that exists today is [`days/2026/05/2026-05-09_Albiriox-Android-MaaS-AcVNC/kill_chain.svg`](./days/2026/05/2026-05-09_Albiriox-Android-MaaS-AcVNC/kill_chain.svg).
7. `## Stage-by-stage detail` — sub-heading per stage with real commands, hashes, paths.
8. `## RE notes` *(optional — only if a public sample exists)*.
9. `## Detection strategy` — telemetry that matters + detection coverage table + threat hunting hypotheses.
10. `## Incident response playbook` — five sub-sections (NIST 800-61): triage, artifacts, IR commands, containment, recovery validation.
11. `## IOCs` — top indicators in a table; full set in `iocs.csv`.
12. `## Secondary findings` — 2–3 short bullets with the week's other relevant incidents.
13. `## Pedagogical anchors` — 3–5 bullets with the durable lesson.
14. `## What's in this folder` — table linking every file in the day folder.
15. `## Sources` — 5–10 Markdown links in standard `[Title]` plus URL format, mostly vendor blog posts and CISA advisories.

---

## Rule metadata standard

Every Sigma rule must include:

```yaml
title:        # imperative, < 80 chars
id:           # UUID v4
status:       # experimental | test | stable | deprecated
description:  # 2–4 lines, plain English, what + why
references:
  - https://...
author:       # Jarmi
date:         # YYYY/MM/DD
tags:
  - attack.<tactic>          # use hyphens, not underscores
  - attack.<technique-id>
logsource:    # generic categories (process_creation, image_load, file_event, network_connection, registry_set)
detection:
  ...
falsepositives:
  - ...                      # always at least one — be honest
level:        # informational | low | medium | high | critical
```

Every KQL file starts with a header comment block:

```kql
// Title:        Lateral Movement via Rubeus S4U2self with TGS Burst
// Id:           uuid-v4
// MITRE:        T1558.003, T1550.003
// Reference:    https://...
// Author:       Jarmi
// Date:         2026-05-04
// Tested on:    Sentinel (DeviceProcessEvents, SecurityEvent)
// FP notes:     Legitimate constrained delegation cases; baseline before deploy.
```

Every YARA rule keeps the `meta:` block populated with `author = "Jarmi"`, `description`, `date`, `reference`, `confidence` and `family`. Every declared `$string` must be referenced in `condition:`.

Suricata 7.x is the target version: `dsize:X<>Y` for ranges, HTTP modifiers as sticky buffers (`http.method; content:"POST";`), unique `sid`, `msg:"..."` always in English.

---

## How to use

### Microsoft Sentinel / Defender XDR

```kql
// Drop the .kql contents into:
// Sentinel → Analytics → Create → Scheduled query rule
// or Defender XDR → Hunting → Custom detection rule
```

### Sigma → vendor target

```bash
pip install pysigma pysigma-backend-microsoft365defender
sigma convert -t microsoft365defender days/2026/05/2026-05-04_C0063-Poland-Wiper/sigma/*.yml
```

If you operate Splunk, run `sigma convert -t splunk -p sysmon <rule>.yml` against the Sigma files on your side. The repo no longer ships `.spl` artifacts — see the CHANGELOG entry from 2026-05-11 for rationale.

### YARA — scan a triage image

```bash
yara -r days/2026/05/2026-05-04_C0063-Poland-Wiper/yara/*.yar /mnt/triage/
```

### Suricata — load a ruleset

```bash
suricata -T -S days/2026/05/2026-05-11_UAT-8302-China-Government-Espionage/suricata/uat8302_c2_domains_subnet.rules
```

---

## Validation

Validation runs **locally before each commit** — no CI involved. Three entry points:

```bash
# 1) Quick offline check — no external tools, just PyYAML
python3 tools/validate_all.py

# 2) Full chain — runs offline check + every external tool you have installed
./tools/lint_all.sh

# 3) Sigma-only quick path (fast)
./tools/lint_sigma.sh
```

What gets validated:

| Format | Offline (`validate_all.py`) | External tool (`lint_all.sh`) |
|---|---|---|
| Sigma `.yml` | UUID, status, level, modifiers, condition refs | `sigma check` |
| YARA `.yar` | rule blocks, brace balance, `condition:` section, dup names | `yara -w rule.yar /dev/null` |
| Suricata `.rules` | action, sid uniqueness, body, msg/rev | `suricata -T -S rule.rules` |
| KQL `.kql` | bracket balance, header comments, keyword presence, trailing-pipe | — |
| CSV `iocs.csv` | header schema, row width | — |
| YAML | strict load | — |
| Markdown | broken relative links | `markdownlint` |
| Bash `.sh` | `bash -n` if available | `shellcheck` |

Recommended install for the full local chain:

```bash
pip install --user pysigma sigma-cli \
            pysigma-backend-microsoft365defender pysigma-pipeline-sysmon yamllint
sudo apt-get install -y yara suricata shellcheck
npm install -g markdownlint-cli
```

---

## Test before you ship

Every rule should be exercised — at minimum mentally — against [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests for the same technique IDs.

When in doubt, follow the [PEAK Threat Hunting Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html):

1. **Prepare** — what hypothesis am I testing?
2. **Execute** — run the hunt, baseline, refine.
3. **Act on Knowledge** — promote to detection, document false-positive surface, harden.

---

## Index

See [`INDEX.md`](INDEX.md) for the chronological + thematic index of all cases.

---

## Source policy

- **Triangulate.** Every case must reference at least two independent sources (vendor write-up + agency advisory, or two vendors with overlap).
- **Cite primary.** Always link to the original write-up, not aggregator headlines.
- **Mark confidence.** When attribution is contested, document both views and the evidence each anchors on.
- **Never invent IOCs, hashes or CVEs.** If a hash isn't published, the rule is heuristic and labelled as such.

---

## Contributing

This is primarily a personal notebook, but PRs that fix typos, broken links, FP-surface notes or that tighten a r