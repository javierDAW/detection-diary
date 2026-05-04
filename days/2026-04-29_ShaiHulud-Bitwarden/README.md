---
date: 2026-04-29
title: "Shai-Hulud: The Third Coming (Bitwarden CLI 2026.4.0)"
clusters:
  - "TeamPCP"
cluster_country: "e-crime / supply-chain"
techniques_enterprise:
  - T1195.002
  - T1059.007
  - T1059.004
  - T1204.002
  - T1546.004
  - T1027
  - T1552.001
  - T1552.005
  - T1528
  - T1083
  - T1005
  - T1102
  - T1567.001
  - T1531
techniques_ics:
platforms:
  - linux
  - macos
  - supply-chain
  - cloud-multi
sectors:
  - software-developers
  - ci-cd
---

# 2026-04-29 — Shai-Hulud: The Third Coming (Bitwarden CLI 2026.4.0 trojanized)

> npm worm-class supply chain: trojanized `bw` CLI uses Bun runtime + `bw1.js` (~10 MB minified) to harvest cloud / CI / AI-CLI secrets and exfiltrate via public GitHub repos under the victim's account.

## Cluster
**TeamPCP** — financially motivated cluster, same actor that pivots into VECT 2.0 RaaS via Trivy GHA / Checkmarx KICS / LiteLLM 1.82.7-8 / Telnyx SDK 4.87.1-2 supply-chain compromises (see day 4).

## What changed vs. previous Shai-Hulud waves
- **Bun runtime** instead of plain Node.js — evades node-aware EDR module hooks.
- **AI-CLI configs added to the secret target list** (Claude Code, Codex, Cursor, Gemini) — first-of-its-kind in npm worm history.
- Exfiltration via public repos under the victim's GitHub account (signature: `Shai-Hulud: The Third Coming`).
- C2 look-alike domain: `audit.checkmarx[.]cx`.

## Kill chain (MITRE ATT&CK Enterprise)

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1195.002 | Trojanized package on npm |
| Execution | T1059.007 (JS) · T1059.004 (sh) · T1204.002 | Loader `bw_setup.js` + Bun + `bw1.js` |
| Persistence | T1546.004 | Shell profile modification (`.bashrc`, `.zshrc`, `.profile`) |
| Defense Evasion | T1027 | Heavy minification, single-line ~10 MB |
| Credential Access | T1552.001 · T1552.005 · T1528 | Files (config/secrets), cloud creds, OAuth tokens |
| Discovery | T1083 | File and directory discovery on creds dirs |
| Collection | T1005 | Local data collection |
| C2 | T1102 | Web service (GitHub) as dead-drop |
| Exfiltration | T1567.001 | Exfil over public code-repository service |
| Impact | T1531 | Account access removal in some variants |

## Highlights
- **Bun loader** is the new evasion frontier — your endpoint hooks for `node` won't fire.
- **AI-CLI config theft** = new asset class to defend (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.config/gemini-cli/`).
- **Public-repo exfil** is hard to block downstream — must be caught at the npm lifecycle stage.

## What's in this folder

| File | Description |
|---|---|
| [`sigma/npm_lifecycle_network_egress.yml`](sigma/npm_lifecycle_network_egress.yml) | npm/Bun lifecycle network egress + shell profile mod |
| [`kql/github_repo_create_shai_hulud.kql`](kql/github_repo_create_shai_hulud.kql) | Sentinel — anomalous repo creation with marker readme |
| [`spl/osquery_node_bun_egress.spl`](spl/osquery_node_bun_egress.spl) | Splunk — osquery process tree node/bun → curl/git/wget |
| [`yara/ShaiHulud_BunLoader_Heuristic.yar`](yara/ShaiHulud_BunLoader_Heuristic.yar) | Bun-loader + Shai-Hulud marker heuristic |
| [`iocs.csv`](iocs.csv) | IOC table |

> **Note on rule provenance.** Reconstructed from the class journal. Tune to your environment before deploying.

## Sources

- [JFrog Security Research — Bitwarden CLI 2026.4.0 trojan analysis](https://research.jfrog.com/)
- [Endor Labs — Shai-Hulud third wave](https://www.endorlabs.com/)
- [Bitwarden security advisory (22-apr-2026)](https://bitwarden.com/blog/)
- [Checkmarx Open Source Security feed](https://checkmarx.com/blog/)
