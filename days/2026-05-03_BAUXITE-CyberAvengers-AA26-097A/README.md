---
date: 2026-05-03
title: "BAUXITE / CyberAv3ngers vs Rockwell PLC (CISA AA26-097A) + ZionSiphon"
clusters:
  - "BAUXITE"
  - "CyberAv3ngers"
  - "Storm-0784"
  - "UNC5691"
  - "Hydro Kitten"
  - "Shahid Kaveh Group"
  - "G1027"
cluster_country: "Iran-nexus (IRGC-CEC)"
techniques_enterprise:
  - T1595
  - T1588.005
  - T1190
  - T1078.001
  - T1133
  - T1059.004
  - T1505.003
  - T1037.004
  - T1098
  - T1018
  - T1046
  - T1021.004
  - T1071.001
  - T1095
  - T1573.002
  - T1565.001
  - T1485
  - T1495
  - T1561
techniques_ics:
  - T0832
  - T0831
platforms:
  - ot-ics
  - plc
  - network-edge
  - windows
sectors:
  - water-wastewater
  - energy
  - government
  - desalination-il
---

# 2026-05-03 — BAUXITE / CyberAv3ngers (IRGC-CEC) — Rockwell PLC direct attack — CISA AA26-097A

> Iran-nexus IRGC OT/IoT attacks on Water & Wastewater, Energy and municipal targets. Direct-to-PLC over EIP/CIP using Rockwell Studio 5000 Logix Designer (legitimate engineering tool). Israeli desalination targeted with **ZionSiphon** (broken comparator — likely LLM-assisted). Censys: 5 219 EIP hosts exposed (74.6 % USA).

## Cluster (alias-merge)
**BAUXITE** (Dragos) = **CyberAv3ngers** = **Storm-0784** (Microsoft) = **UNC5691** (Mandiant) = **Hydro Kitten** (CrowdStrike) = **Shahid Kaveh Group** (FBI) = **MITRE G1027**.

## Sectors / geography
- Water & Wastewater Systems (US municipalities)
- Energy
- Government Services & Facilities
- Israeli desalination plants (Mekorot / Sorek / Hadera / Ashdod / Palmachim / Shafdan) — ZionSiphon

## Tradecraft
- **Direct-to-PLC** via **Studio 5000 Logix Designer** (legit engineering tool) over EIP TCP/44818 + 2222
- Extract → modify → redeploy `.ACD` ladder logic project files
- **HMI/SCADA display falsification** (T0832 Manipulation of View)
- **Dropbear SSH** deployed *on the PLC* on TCP/22 as persistence (T1505.003 + T1037.004)
- Pivot via **cellular gateways** (Sierra Wireless AirLink — overlaps with VOLTZITE / Volt Typhoon)
- **IOCONTROL** (Claroty Team82, evolved 2026): ELF multi-arch on D-Link / Hikvision / Red Lion / Orpak / Phoenix Contact / Teltonika; C2 = MQTT TLS TCP/8883
- **ZionSiphon** PE Win64 — `EncryptDecrypt("Israel",5)` does NOT produce hardcoded comparator `Nqvbdk` → broken; probable LLM-assisted; partial SHA256 `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f3...`

## Kill chain (MITRE ATT&CK Enterprise + ICS)

| Tactic | Technique |
|---|---|
| Reconnaissance | T1595 |
| Resource Development | T1588.005 |
| Initial Access | T1190 · T1078.001 · T1133 |
| Execution | T1059.004 |
| Persistence | T1505.003 · T1037.004 · T1098 |
| Discovery | T1018 · T1046 |
| Lateral Movement | T1021.004 |
| C2 | T1071.001 · T1095 · T1573.002 |
| Impact | T1565.001 · T1485 · T1495 · T1561 · **T0831** · **T0832** |

## Pedagogical anchors
- Today no OT 0day is needed — **PLC on the Internet + vendor SDK + default creds** is enough.
- **HMI is not ground truth during IR** (display falsification is active).
- **DO NOT power off the PLC** during triage without coordinating with safety/operations (physical risk).
- Cellular ASN co-exposure = a frequently forgotten vector.

## What's in this folder

| File | Description |
|---|---|
| [`sigma/rockwell_studio5000_outbound.yml`](sigma/rockwell_studio5000_outbound.yml) | Studio 5000 / RSLogix / RSLinx → 44818/2222/502 to public destination |
| [`suricata/bauxite_dropbear.rules`](suricata/bauxite_dropbear.rules) | Dropbear SSH banner FROM OT host + external CIP `List Identity` to OT |
| [`kql/engineering_tool_egress.kql`](kql/engineering_tool_egress.kql) | Sentinel — engineering tool egress + Dropbear file drop dual-channel |
| [`yara/ZionSiphon_Targeting_Strings_Heuristic.yar`](yara/ZionSiphon_Targeting_Strings_Heuristic.yar) | Israeli target list + broken comparator + ICS APIs |
| [`iocs.csv`](iocs.csv) | IOC table |

> **Note on rule provenance.** Reconstructed from the class journal. Tune to your environment before deploying.

## Sources

- [CISA AA26-097A — Iran-affiliated cyber threat actors targeting US WWS sector (FBI+CISA+NSA+EPA+DOE+CNMF, 7-apr-2026)](https://www.cisa.gov/news-events/cybersecurity-advisories/)
- [Censys — IRGC-CEC follow-up (5 219 EIP hosts exposed, 74.6 % US)](https://censys.com/blog/)
- [Darktrace — ZionSiphon vs Israeli desalination (apr-2026)](https://darktrace.com/blog)
- [Krypt3ia — IRGC OT/IoT malware evolution (30-apr-2026)](https://krypt3ia.wordpress.com/)
- [Dragos — BAUXITE Year in Review 2026](https://www.dragos.com/year-in-review/)
- [Claroty Team82 — IOCONTROL (2024+)](https://claroty.com/team82)
- [MITRE ATT&CK — G1027 CyberAv3ngers](https://attack.mitre.org/groups/G1027/)
