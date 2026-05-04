---
date: 2026-05-01
title: "VECT 2.0 RaaS — wiper-by-accident"
clusters:
  - "VECT"
  - "TeamPCP"
  - "BreachForums"
cluster_country: "e-crime / RaaS"
techniques_enterprise:
  - T1195.002
  - T1078
  - T1059.001
  - T1059.003
  - T1129
  - T1562.001
  - T1562.002
  - T1562.004
  - T1497
  - T1027
  - T1070.001
  - T1003.001
  - T1552.001
  - T1518
  - T1057
  - T1614.001
  - T1021.004
  - T1547.001
  - T1543.003
  - T1134.001
  - T1486
  - T1485
  - T1490
  - T1561.002
  - T1529
techniques_ics:
platforms:
  - windows
  - linux
  - esxi
sectors:
  - mixed-enterprise
---

# 2026-05-01 — VECT 2.0 RaaS — *Ransomware by design, Wiper by accident*

> A RaaS payload with a fatal cryptographic flaw: 4 nonces share one buffer in chunked ChaCha20-IETF mode → only the last nonce persists → first 3 chunks are unrecoverable even by the operator. Acts as a **wiper** for any file > 128 KB.

## Cluster
**VECT × TeamPCP × BreachForums** (alliance formalized 16-apr-2026 per Dataminr). BreachForums acts as escrow + key-distribution infra; any forum user effectively becomes an affiliate.

## Connection to day 2 (29-apr-2026)
TeamPCP is the actor behind *Shai-Hulud Bitwarden*. Their CI/CD supply-chain compromises (Trivy GHA, Checkmarx KICS, LiteLLM 1.82.7-8, Telnyx SDK 4.87.1-2 in March 2026) are the **entry vector** to VECT.

## Payloads
- `svchostupdate.exe` — Windows
- `encesxi.elf` — Linux / ESXi
- C++ + statically-linked libsodium

## The bug (teaching anchor)
ChaCha20-IETF (RFC 8439, **raw, no Poly1305 AEAD**) with 4 chunks/nonces for files > 131 072 B (128 KB). All four nonces are written to **the same shared buffer** → only the last persists → first 3 chunks are irrecoverably mangled. Victim cannot recover files > 128 KB even if they pay.

## Operational details
- **Local killswitch:** `C:\ProgramData\.vect` (Win) / `/var/run/.vect` (Linux)
- **Transient persistence:** `bcdedit /set {default} safeboot minimal` + `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\<svc>` (residual key = gold IOC)
- **EVTX clearing** with XOR key `0xBB55FF59DF597B8D` over Application/Security/System/PowerShell
- **ESXi geofencing** via `timedatectl`, `LANG`, `LC_ALL` excluding CIS states
- **SSH lateral:** `--ssh-keyfile`, `--ssh-userlist`, `~/.ssh/known_hosts`

## Kill chain (MITRE ATT&CK Enterprise)

| Tactic | Technique |
|---|---|
| Initial Access | T1195.002 · T1078 |
| Execution | T1059.001 · T1059.003 · T1129 |
| Persistence | T1547.001 · T1543.003 |
| Defense Evasion | T1562.001 · T1562.002 · T1562.004 · T1497 · T1027 · T1070.001 |
| Credential Access | T1003.001 · T1552.001 |
| Discovery | T1518 · T1057 · T1614.001 |
| Lateral Movement | T1021.004 |
| Privilege Escalation | T1134.001 |
| Impact | T1486 (intent) · T1485 (effect) · T1490 · T1561.002 · T1529 |

## Pedagogical anchor
The victim **cannot recover** files > 128 KB even if paying. IR playbook must explicitly state **"do not negotiate"**. Only partial recovery window = **key in RAM** captured before the process exits.

## What's in this folder

| File | Description |
|---|---|
| [`sigma/vect_safeboot_bcdedit.yml`](sigma/vect_safeboot_bcdedit.yml) | Sigma — bcdedit safeboot minimal (process_creation) |
| [`sigma/vect_safeboot_regset.yml`](sigma/vect_safeboot_regset.yml) | Sigma — SafeBoot\Minimal\<svc> reg add (registry_set) |
| [`sigma/vect_killswitch_marker.yml`](sigma/vect_killswitch_marker.yml) | Sigma — `C:\ProgramData\.vect` marker (file_event) |
| [`sigma/vect_safeboot_persistence.yml`](sigma/vect_safeboot_persistence.yml) | **DEPRECATED** tombstone — replaced by the 3 atomic rules above. `git rm` before pushing if you want a clean repo. |
| [`kql/vect_mass_process_kill.kql`](kql/vect_mass_process_kill.kql) | Defender XDR / Sentinel — mass termination of DB / office / browser processes in 60-s window |
| [`spl/vect_marker_bcdedit_safeboot.spl`](spl/vect_marker_bcdedit_safeboot.spl) | Splunk — combined marker + bcdedit + SafeBoot reg correlation |
| [`yara/VECT2_ChaCha20_Nonce_Bug_Heuristic.yar`](yara/VECT2_ChaCha20_Nonce_Bug_Heuristic.yar) | YARA — multi-platform PE+ELF heuristic (XOR key + libsodium + .vect) |
| [`iocs.csv`](iocs.csv) | IOC table |

> **Note on rule provenance.** Reconstructed from the class journal. Tune to your environment before deploying.

## Sources

- [Check Point Research — VECT 2.0 RaaS (28-apr-2026)](https://research.checkpoint.com/)
- [Dataminr — VECT × TeamPCP × BreachForums alliance (16-apr-2026)](https://www.dataminr.com/)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
