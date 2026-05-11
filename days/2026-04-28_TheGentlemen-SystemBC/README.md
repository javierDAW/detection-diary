---
date: 2026-04-28
title: "The Gentlemen RaaS + SystemBC"
clusters:
  - "The Gentlemen"
cluster_country: "e-crime / RaaS"
techniques_enterprise:
  - T1078
  - T1190
  - T1059.001
  - T1059.003
  - T1053.005
  - T1543.003
  - T1484.001
  - T1562.001
  - T1562.002
  - T1562.004
  - T1003.001
  - T1046
  - T1482
  - T1021.001
  - T1021.002
  - T1021.006
  - T1090.002
  - T1573.001
  - T1041
  - T1486
  - T1490
techniques_ics:
platforms:
  - windows
  - active-directory
sectors:
  - mixed-enterprise
---

# 2026-04-28 — The Gentlemen RaaS + SystemBC

> Custom RC4 SOCKS5 proxy + GPO weaponization for mass GPO-driven payload distribution. RaaS-class e-crime, DFIR-heavy.

## Cluster
**The Gentlemen** — RaaS affiliate ecosystem; financially motivated; partial overlap reported with post-LockBit affiliates.

## Sectors / geography
Mixed enterprise (Check Point public write-up). Western Europe + North America victims observed.

## Kill chain (MITRE ATT&CK Enterprise)

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1078 · T1190 | Valid accounts via VPN; perimeter exploits |
| Execution | T1059.001 · T1059.003 | PowerShell, cmd |
| Persistence | T1053.005 · T1543.003 · T1484.001 | Scheduled tasks, services, **GPO modification** |
| Defense Evasion | T1562.001 · T1562.004 · T1562.002 | EDR tampering, FW disable, AV component disable |
| Credential Access | T1003.001 | LSASS dump |
| Discovery | T1046 · T1482 | Network scan, AD trust mapping |
| Lateral Movement | T1021.002 · T1021.006 · T1021.001 | SMB, WinRM, RDP |
| Command and Control | T1090.002 · T1573.001 | **SystemBC custom RC4 SOCKS5** + symmetric encryption |
| Exfiltration | T1041 | Over C2 channel |
| Impact | T1486 · T1490 | Encryption + recovery inhibition |

## Highlights / what to study
- **SystemBC** custom RC4-encrypted SOCKS5 proxy beaconing over plain TCP (no TLS) — this is the *teaching anchor* for "TCP egress without TLS to commodity port" detections.
- **GPO weaponization** for mass deployment — the technique we keep seeing across e-crime *and* state actors (compare against day 4 VECT 2.0 and day 7 C0063).
- X25519 + XChaCha20 ransomware encryption (modern AEAD, no rookie crypto bugs here — contrast with day 4 VECT).

## What's in this folder

| File | Description |
|---|---|
| [`sigma/gpo_weaponization_systembc.yml`](sigma/gpo_weaponization_systembc.yml) | GPO mass changes (gPLink + startup script writes) |
| [`kql/tcp_beacon_no_tls_systembc.kql`](kql/tcp_beacon_no_tls_systembc.kql) | Sentinel — heuristic for plain-TCP beacon without TLS |
| [`yara/SystemBC_RC4_Heuristic.yar`](yara/SystemBC_RC4_Heuristic.yar) | SystemBC RC4-protocol heuristic for memory / disk |
| [`iocs.csv`](iocs.csv) | IOC table |

> **Note on rule provenance.** The rules in this folder were reconstructed from the class journal (TTPs, paths, command lines, MITRE IDs documented at delivery time). They are *equivalent* to the rules originally delivered, not necessarily byte-identical. Tune to your environment before deploying.

## Sources

- [Check Point Research — The Gentlemen RaaS / SystemBC analysis (27-apr-2026)](https://research.checkpoint.com/) — primary write-up
- [MITRE ATT&CK — Group profile (e-crime)](https://attack.mitre.org/)
- [SigmaHQ rules — T1484.001 baseline](https://github.com/SigmaHQ/sigma)
