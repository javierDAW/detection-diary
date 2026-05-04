# detection-diary

> Daily detection content — Sigma, KQL, SPL and YARA — derived from real-world threat intel write-ups. One case per day, MITRE ATT&CK mapped, sources cited.

[![Sigma](https://img.shields.io/badge/Sigma-rules-blue)](https://github.com/SigmaHQ/sigma)
[![KQL](https://img.shields.io/badge/KQL-Sentinel%20%7C%20Defender%20XDR-0078D4)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![SPL](https://img.shields.io/badge/SPL-Splunk-black)](https://docs.splunk.com/Documentation/SCS/current/Search/Aboutsearchlanguage)
[![YARA](https://img.shields.io/badge/YARA-rules-yellow)](https://yara.readthedocs.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What this is

This repository is my personal **detection journal**: every day I take one high-impact, technically meaty case from the threat intel feed (vendor write-ups from Mandiant, Microsoft, Volexity, Unit 42, ESET, Talos, Securelist, SentinelOne, CrowdStrike, Dragos, etc., plus DFIR Report and CISA advisories) and translate it into **deployable detection content**:

- **Sigma** rules (vendor-agnostic, convertible via `pySigma`/`uncoder`/`sigmac`)
- **KQL** queries (Microsoft Sentinel and Defender XDR)
- **SPL** queries (Splunk Enterprise / ES)
- **YARA** rules (file/process memory)
- **Suricata / Snort** signatures — when relevant
- **PEAK / TaHiTI hunting hypotheses** with baselines

Each entry is grounded on a published, sourced case so it stays defensible and reproducible.

---

## What this is **not**

- Not a feed for production blocklists. Validate every IOC before wiring it into preventive controls — confidence levels are documented, but circumstances change.
- Not a SigmaHQ replacement. Upstream-quality rules go to [SigmaHQ](https://github.com/SigmaHQ/sigma) via PR; this is the **lab notebook** that precedes that step.
- Not weaponized PoCs. All offensive snippets here are publicly documented and live for **detection design**, not exploitation.

---

## Repository layout

```
detection-diary/
├── README.md
├── INDEX.md                ← AUTO-GENERATED — chronological + by-actor + by-technique + by-platform
├── CHANGELOG.md
├── LICENSE
├── .gitignore
│
├── days/                   ← source of truth — one folder per case
│   └── YYYY-MM-DD_<slug>/
│       ├── README.md       ← YAML frontmatter at the top is the canonical metadata
│       ├── sigma/*.yml
│       ├── kql/*.kql
│       ├── spl/*.spl
│       ├── yara/*.yar
│       ├── suricata/*.rules
│       ├── hunts/*.md
│       └── iocs.csv
│
├── byActor/                ← AUTO-GENERATED view: one folder per cluster/alias
│   ├── README.md
│   └── <slug>/README.md
│
├── byTechnique/            ← AUTO-GENERATED view: one folder per MITRE ATT&CK ID
│   ├── README.md
│   └── txxxx/README.md
│
├── byPlatform/             ← AUTO-GENERATED view: one folder per platform tag
│   ├── README.md
│   └── <slug>/README.md
│
├── .github/workflows/
│   ├── sigma-lint.yml      ← Sigma-only quick CI
│   └── validate.yml        ← full multi-format CI
│
└── tools/
    ├── validate_all.py     ← offline multi-format validator (Sigma, YARA, Suricata, KQL, SPL, CSV, YAML, MD, Bash)
    ├── sigma_check.py      ← Sigma-only offline validator (PyYAML-only dep)
    ├── lint_sigma.sh       ← Sigma wrapper: sigma-cli if installed, else falls back to sigma_check.py
    ├── lint_all.sh         ← full chain wrapper
    └── generate_index.py   ← rebuilds INDEX.md + byActor/ + byTechnique/ + byPlatform/ from frontmatter
```

> The folders **`INDEX.md`, `byActor/`, `byTechnique/` and `byPlatform/` are
> auto-generated** from the YAML frontmatter at the top of each
> `days/<slug>/README.md`. To rebuild them after adding or editing a day:
>
> ```bash
> python3 tools/generate_index.py
> ```
>
> Do not edit those files by hand — your changes will be wiped on the next
> regen. Edit the day's frontmatter instead, or the day's README content
> below the frontmatter.


---

## Naming convention

```
days/YYYY-MM-DD_<short-slug>/
```

- `YYYY-MM-DD` is the date the **class was delivered**, not the date the case was disclosed.
- `<short-slug>` is the campaign ID, malware family, or actor (kebab-case). Examples:
  - `2026-05-04_C0063-Poland-Wiper`
  - `2026-05-03_BAUXITE-CyberAvengers-AA26-097A`
  - `2026-05-02_Nexcorium-TBK-DVR-CVE-2024-3721`

Rule files inside follow:

```
<technique-or-payload>.<ext>
```

---

## Rule metadata standard

Every Sigma rule must include:

```yaml
title:        # imperative, < 80 chars
id:           # UUID v4
status:       # experimental | test | stable | deprecated
description:  # 2–4 lines, plain English, what + why
references:
  - https://...    # primary vendor write-up
  - https://...    # secondary corroboration
  - https://attack.mitre.org/...
author:       # your handle
date:         # YYYY/MM/DD
modified:     # YYYY/MM/DD
tags:
  - attack.<tactic>
  - attack.<technique-id>
  - cve.YYYY-NNNN   # if applicable
logsource:    # exact provider/service/category
detection:
  ...
falsepositives:
  - ...        # always at least one — be honest
level:        # informational | low | medium | high | critical
```

Every KQL/SPL file starts with a header comment block:

```kql
// Title:        Lateral Movement via Rubeus S4U2self with TGS Burst
// Id:           uuid-v4
// MITRE:        T1558.003, T1550.003
// Reference:    https://...
// Author:       <handle>
// Date:         2026-05-04
// Tested on:    Sentinel (DeviceProcessEvents, SecurityEvent)
// FP notes:     Legitimate constrained delegation cases; baseline before deploy.
```

Every YARA rule keeps the `meta:` block populated with `author`, `description`, `date`, `reference`, `confidence`, and (where relevant) `eset_family` / `vendor_family`.

---

## How to use

### Microsoft Sentinel / Defender XDR

```kql
// Drop the .kql contents into:
// Sentinel → Analytics → Create → Scheduled query rule
// or Defender XDR → Hunting → Custom detection rule
```

### Splunk Enterprise / ES

```bash
# Save the .spl as a Saved Search, scheduled run.
# For Splunk ES, wire into a Correlation Search and assign Risk-Based Alerting.
```

### Sigma → vendor target

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-microsoft365defender
sigma convert -t splunk days/2026-05-04_C0063-Poland-Wiper/sigma/*.yml
sigma convert -t microsoft365defender days/2026-05-04_C0063-Poland-Wiper/sigma/*.yml
```

### YARA — scan a triage image

```bash
yara -r days/2026-05-04_C0063-Poland-Wiper/yara/*.yar /mnt/triage/
```

---

## Validation

Every commit and pull request runs the full validation chain in CI
([`.github/workflows/validate.yml`](.github/workflows/validate.yml)). Locally:

```bash
# 1) Quick offline check — no external tools, just PyYAML
python3 tools/validate_all.py

# 2) Full chain — runs offline check + every external tool you have installed
./tools/lint_all.sh

# 3) Sigma-only quick path (legacy)
./tools/lint_sigma.sh
```

What gets validated:

| Format | Offline (`validate_all.py`) | External tool (`lint_all.sh`) |
|---|---|---|
| Sigma `.yml` | UUID, status, level, modifiers, condition refs | `sigma check` + `sigma convert -t splunk -p sysmon` |
| YARA `.yar` | rule blocks, brace balance, `condition:` section, dup names | `yara -w rule.yar /dev/null` |
| Suricata `.rules` | action, sid uniqueness, `(...;)` body, msg/rev | `suricata -T -S rule.rules` |
| KQL `.kql` | bracket balance, header comments, keyword presence, trailing-pipe | — |
| SPL `.spl` | bracket balance, command after pipe, header comment | — |
| CSV `iocs.csv` | header schema, row width | — |
| YAML | strict load (workflows + Sigma + every `.yml`) | — |
| Markdown | broken relative links | `markdownlint` |
| Bash `.sh` | `bash -n` if available | `shellcheck` |
| GitHub Actions | YAML load | `actionlint` |

Recommended install for the full local chain:

```bash
pip install --user pysigma sigma-cli pysigma-backend-splunk \
            pysigma-pipeline-sysmon yamllint
sudo apt-get install -y yara suricata shellcheck
bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)
sudo install -m 0755 actionlint /usr/local/bin/actionlint
npm install -g markdownlint-cli
```

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
- **Mark confidence.** When attribution is contested (e.g., Static Tundra vs. Sandworm for C0063), document both views and the evidence each anchors on.
- **Never invent IOCs, hashes, or CVEs.** If a hash isn't published, the rule is heuristic and labelled as such.

---

## Contributing

This is primarily a personal notebook, but PRs that