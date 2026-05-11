---
date: 2026-05-07
title: "EVM/DeFi npm typosquatting — six packages by namikazesarada010206 (Xygeni, 6-may-2026)"
clusters:
  - "namikazesarada010206"
  - "harunosakura030303-maker"
cluster_country: "Unattributed (e-crime hypothesis — credential-first / opportunistic supply-chain)"
techniques_enterprise:
  - T1583.001
  - T1583.006
  - T1587.001
  - T1608.001
  - T1195.002
  - T1059.007
  - T1129
  - T1027
  - T1480
  - T1140
  - T1083
  - T1518
  - T1552.001
  - T1552.004
  - T1555.005
  - T1539
  - T1005
  - T1071.001
  - T1573.001
  - T1041
  - T1657
platforms:
  - linux
  - macos
  - windows
  - supply-chain
  - cloud-multi
sectors:
  - software-development
  - cryptocurrency
  - defi
  - finance
---

# EVM/DeFi npm typosquatting — `namikazesarada010206` (Xygeni, 2026-05-06)

**Author:** Jarmi
**Date:** 2026-05-07
**Class:** Day 11 — Thursday supply-chain slot (complementary to QLNX from the same day — *upstream RAT* vs *downstream typosquat*).

## Executive summary

Six npm packages — `viem-core`, `viem-utils-core`, `hardhat-core-utils`, `evm-utils`, `foundry-utils`, `web3-utils-core` — were all published as `1.0.0` within a 57-second window (2026-05-06 01:38:44 → 01:39:48 UTC) by the publisher `namikazesarada010206`, with email `namikazesarada010206@gmail.com` and repository `github.com/harunosakura030303-maker/evmchain-config`. They target the **Ethereum / Solidity / Hardhat / Foundry / Brownie** developer ecosystem.

Unlike the usual typosquat pattern with `postinstall`, **the malware activates when the developer issues `require()`/`import` against the module from their own project** — a *brand-adjacency squat* with late activation: it bypasses `npm install --ignore-scripts` and most CI scanning hooks.

The payload (`telemetry.js`, **SHA-256 `71426e93cb6143052d5aeeca920850f8a0343c95bc65aab9a15145848cc5bff1`**, byte-identical across all 6 packages) implements:

- **Activation gate** based on environment variables (`ALCHEMY_API_KEY`, `INFURA_KEY`, `PRIVATE_KEY`, `MNEMONIC`, `DEPLOYER_KEY`) or local presence of Foundry / Hardhat / Brownie configs.
- **Credential vacuum:** `~/.ssh/id_*`, `~/.aws/credentials`, `~/.npmrc`, `~/.foundry/keystores/*`, `~/.ethereum/keystore/*`, `~/.brownie/accounts/*`, `.env*` shallow-recursive from cwd.
- **Encryption** with AES-256-GCM (hardcoded passphrase).
- **Exfiltration** via POST to `https://76.13.37.80/...` with `NODE_TLS_REJECT_UNAUTHORIZED=0` (TLS verify off — literal IP, no valid cert).
- **No retry / no fallback / no local persistence** — single-shot.

Attribution: **low confidence**. No public link to known clusters (TeamPCP / DPRK / etc.). Tactical fit with the 2026 trend of **credential-first opportunistic supply-chain** (cf. *Mini Shai-Hulud*, *Ghost Campaign*).

## Kill chain — quick map

| Stage | MITRE | Detail |
|---|---|---|
| Resource Development | T1583.001 / T1583.006 / T1587.001 / T1608.001 | npm + GitHub accounts; custom payload; registry upload |
| Initial Access | T1195.002 | Voluntary `npm install <pkg>` by the developer |
| Execution | T1059.007, T1129 | JS via `require()` → `index.js` → `require('./telemetry')` |
| Defense Evasion | T1027, T1480, T1140 | Activation gate (env-var + config sniff), TLS verify off, errors silently swallowed |
| Discovery | T1083, T1518 | Foundry/Hardhat/Brownie sniff + filesystem walk |
| Credential Access | T1552.001, T1552.004, T1555.005, T1539 | `.env*`, SSH keys, wallet keystores, AWS creds, npm token |
| Collection | T1005 | In-memory JSON bundle |
| C2 / Exfil | T1071.001, T1573.001, T1041 | HTTPS POST to literal IPv4 with payload-level AES-256-GCM |
| Impact | T1657 (financial theft) | On-chain drain after exfil |

## Key pedagogical takeaways

- **`npm install --ignore-scripts` does NOT mitigate this vector.** The package needs no `postinstall`. Activation lives in the developer's own `require()`.
- **The offending process on host is `node`**, not `npm`. Your telemetry must hunt the child of Hardhat/Foundry/IDE.
- **Brand-adjacency squat ≠ classic typosquat.** Names are not character flips — they are plausible suffixes (`-core`, `-utils`, `-utils-core`). Prevention watchlists must model the "supplemental name vs real library" pattern.
- **Once exfil happens, the attacker has already won.** Do not wait to "clean" the box — rotate wallets and credentials, and move funds *first*.

## What's in this folder

| File | Type | Purpose |
|---|---|---|
| [README.md](./README.md) | Markdown | This write-up |
| [iocs.csv](./iocs.csv) | IOC table | Hashes, IPv4 C2, packages, accounts |
| [sigma/dev_secret_read_burst_from_node.yml](./sigma/dev_secret_read_burst_from_node.yml) | Sigma | Burst reads of SSH/AWS/npmrc/keystores from a single `node` PID |
| [sigma/node_outbound_ipv4_no_sni.yml](./sigma/node_outbound_ipv4_no_sni.yml) | Sigma | `node` outbound to literal IPv4 (incl. known C2) |
| [yara/evmdefi_npm_typosquat_telemetry.yar](./yara/evmdefi_npm_typosquat_telemetry.yar) | YARA | `telemetry.js` anchors (env-var gate strings + AES-256-GCM + IPv4 + TLS reject) |
| [kql/defender_credential_burst_dev_host.kql](./kql/defender_credential_burst_dev_host.kql) | KQL — Defender XDR | Sensitive file-read burst from `node` on host with dev tooling |
| [kql/sentinel_node_outbound_first_seen_ipv4.kql](./kql/sentinel_node_outbound_first_seen_ipv4.kql) | KQL — Sentinel | First-seen IPv4 outbound from `node` (ASN baseline) |
| [suricata/tls_no_sni_ipv4_literal.rules](./suricata/tls_no_sni_ipv4_literal.rules) | Suricata 7.x | TLS handshake without SNI to literal IPv4 from dev/CI VLAN |
| [hunts/peak_h1_h2.md](./hunts/peak_h1_h2.md) | Hunt | PEAK H1 (Builder bait) and H2 (IP-only egress from dev tooling) |

## Sources

- [Xygeni — EVM/DeFi npm Typosquatting Attack Steals Developer Keys](https://xygeni.io/blog/evm-defi-npm-typosquatting-attack-steals-developer-keys/)
- [Registry npmjs.org/viem-core](https://registry.npmjs.org/viem-core)
- [Registry npmjs.org/viem-utils-core](https://registry.npmjs.org/viem-utils-core)
- [Registry npmjs.org/hardhat-core-utils](https://registry.npmjs.org/hardhat-core-utils)
- [Registry npmjs.org/evm-utils](https://registry.npmjs.org/evm-utils)
- [Registry npmjs.org/foundry-utils](https://registry.npmjs.org/foundry-utils)
- [Registry npmjs.org/web3-utils-core](https://registry.npmjs.org/web3-utils-core)
- [Xygeni — DevTap npm Typosquatting Attack](https://xygeni.io/blog/devtap-npm-typosquatting-attack-2/)
- [BleepingComputer — Palo Alto warns of firewall RCE zero-day (CVE-2026-0300)](https://www.bleepingcomputer.com/news/security/palo-alto-networks-warns-of-actively-exploited-firewall-zero-day/)
- [Help Net Security — Root-level RCE in PAN firewalls exploited (CVE-2026-0300)](https://www.helpnetsecurity.com/2026/05/06/palo-alto-firewalls-vulnerability-exploited-cve-2026-0300/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
