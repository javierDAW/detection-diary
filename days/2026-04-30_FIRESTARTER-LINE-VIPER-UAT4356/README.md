---
date: 2026-04-30
title: "FIRESTARTER + LINE VIPER on Cisco ASA"
clusters:
  - "UAT-4356"
  - "Storm-1849"
  - "ArcaneDoor"
cluster_country: "China-nexus (medium confidence)"
techniques_enterprise:
  - T1190
  - T1059.004
  - T1106
  - T1542.001
  - T1037
  - T1014
  - T1620
  - T1574.006
  - T1027
  - T1082
  - T1071.001
  - T1573.001
  - T1213
  - T1490
  - T1056.004
  - T1040
  - T1110.003
  - T1018
  - T1046
  - T1090.003
techniques_ics:
platforms:
  - network-edge
  - cisco-asa
sectors:
  - us-fceb-agency
---

# 2026-04-30 — FIRESTARTER + LINE VIPER (UAT-4356 / Storm-1849 / ArcaneDoor)

> Persistent implant chain on Cisco Secure Firewall ASA / FTD / Firepower. Survives firmware upgrade, security patches and graceful reboots. Only a *hard power-cycle* dislodges it (with corruption risk).

## Cluster
**UAT-4356 / Storm-1849 / ArcaneDoor** — China-nexus *medium confidence* (not officially confirmed in vendor reports).

## Initial access
- **CVE-2025-20333** — RCE in Cisco WebVPN
- **CVE-2025-20362** — auth bypass

## Implant architecture
- **Stage 1 — LINE VIPER** — user-mode shellcode loader.
- **Stage 2 — FIRESTARTER** — ELF Linux module that hooks the LINA process and persists by **rewriting `/opt/cisco/config/platform/rmdb/CSP_MOUNT_LIST` during the SIGTERM of graceful shutdown**.
- **Trigger:** *passive* — no beacon. POST to WebVPN `/+CSCOE+/` with XML body prefixed by magic bytes → reactivates implant.
- **Genealogy:** overlap with **RayInitiator Stage-3** of the 2024 ArcaneDoor bootkit campaign.
- Discovered in a US FCEB agency. Dwell-time ≥ 6 months.

## Kill chain (MITRE ATT&CK Enterprise)

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1190 | CVE-2025-20333 + CVE-2025-20362 |
| Execution | T1059.004 · T1106 | Native API on ASA Linux |
| Persistence | T1542.001 · T1037 · T1574.006 | Pre-OS / firmware-class; hooks during shutdown |
| Defense Evasion | T1014 · T1620 · T1027 | Rootkit-like, reflective loading |
| Discovery | T1082 | System info recon |
| C2 | T1071.001 · T1573.001 | HTTPS wrapping over WebVPN |
| Collection | T1213 · T1056.004 · T1040 | Credentials in transit |
| Lateral / movement primitives | T1110.003 · T1018 · T1046 · T1090.003 | Password spraying, network discovery |
| Impact | T1490 | Recovery inhibition (config rewrite at shutdown) |

## Pedagogical anchor
- **On-device Sigma DOES NOT WORK** — CISA explicit. Hunt **side-effects** in network and management plane: WebVPN body-size anomalies, ASA reboots correlated to large POSTs, NetFlow showing ASA pivoting internally.
- Don't trust `show running-config` or `show version` after reset — config can be tampered.

## What's in this folder

| File | Description |
|---|---|
| [`sigma/cisco_asa_webvpn_large_post.yml`](sigma/cisco_asa_webvpn_large_post.yml) | Anomalous large POST to `/+CSCOE+/` |
| [`kql/cisco_asa_reboot_webvpn_correlation.kql`](kql/cisco_asa_reboot_webvpn_correlation.kql) | Sentinel — ASA reboot + WebVPN large-body in 30-min window |
| [`yara/FIRESTARTER_ELF_Heuristic.yar`](yara/FIRESTARTER_ELF_Heuristic.yar) | FIRESTARTER ELF + CSP_MOUNT_LIST string heuristic |
| [`iocs.csv`](iocs.csv) | IOC table |

> **Note on rule provenance.** Reconstructed from the class journal. Tune to your environment before deploying.

## Sources

- [CISA AR26-113A — Cisco ASA persistent implant (23-apr-2026)](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [Cisco PSIRT — CVE-2025-20333 / CVE-2025-20362](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [MITRE ATT&CK — ArcaneDoor (2024)](https://attack.mitre.org/)
