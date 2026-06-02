---
date: 2026-06-02
title: "Aur0ra ransomware — in-place encryption with no rename and no extension, double-extortion via Tor"
clusters: ["Aur0ra (unattributed ransomware family)"]
cluster_country: "Unknown"
techniques_enterprise: [T1486, T1490, T1566.001, T1091, T1059, T1497.001, T1564.003, T1027.002, T1055, T1134, T1546.011, T1548, T1012, T1057, T1082, T1120, T1135, T1560, T1071, T1090.003, T1070.006, T1202]
techniques_ics: []
platforms: [windows]
sectors: [cross-sector, enterprise]
---

# Aur0ra ransomware — in-place encryption with no rename and no extension, double-extortion via Tor

## TL;DR

Aur0ra is a newly catalogued Windows (x64) filecoder that CYFIRMA pulled from underground-forum monitoring (Weekly Intelligence Report, 2026-05-22) and that pcrisk independently analysed from a VirusTotal submission (2026-05-07). Its single distinctive behaviour is that it encrypts files **in place** — it does not rename them and does not append any extension, so `1.jpg` stays `1.jpg` but becomes unreadable. It runs a standard pre-encryption playbook (anti-analysis/sandbox checks, removable-media and network-share discovery, Volume Shadow Copy deletion) before dropping a single ransom note named `!!!README!!!DO_NOT_DELETE.txt` that claims data theft and points victims to a Tor negotiation portal with a per-victim access key. It is unattributed — no actor, affiliate program, or victim count is public yet — so this case is a ransomware-family and detection-engineering deep-dive, not an attribution write-up. The why-today: the no-rename design defeats the two cheapest ransomware tripwires most shops rely on (extension-watch rules and canary-file rename triggers), and it lands in the #3 crime-economy slot for a Tuesday.

## Attribution and confidence

| Item | Assessment |
|---|---|
| Cluster | Aur0ra (self-named in ransom note / family name assigned by AV vendors) |
| Attribution | **Unattributed** — no actor or RaaS affiliate program publicly linked |
| Family confidence | **high** (multiple independent vendors describe the same artifacts) |
| Actor confidence | **low** (none named; sourced from forum monitoring + a VT sample) |

Aur0ra is named by its ransom note and by AV family labels rather than by an operator. AV detection names converge on a single family: ESET-NOD32 `Win64/Filecoder.Aur0ra.A`, Microsoft `Ransom:Win32/Genasom!rfn`, Kaspersky `Trojan-Ransom.Win32.Cryptor.gvm`, Avast `Win64:MalwareX-gen [Misc]`, Combo Cleaner `Gen:Heur.Ransom.Imps.1`. CYFIRMA, pcrisk (Tomas Meskauskas) and Tech Jacks Solutions describe the same observable set — in-place encryption with no extension, the note filename `!!!README!!!DO_NOT_DELETE.txt`, a Tor portal, and a per-victim access key — which is why the family is rated high while the operator is left explicitly unknown.

| Overlap candidate | Why mentioned | Confidence |
|---|---|---|
| Generic double-extortion RaaS playbook | VSS deletion + claimed exfil + Tor portal + DLS-style threat is the commodity-RaaS template | n/a (shared TTP, not shared identity) |
| MORTAR / commodity 2026 filecoders | Same week's pcrisk catalogue shows multiple new in-place / generic-note families; no code link asserted | low |

Genealogy with previous repo cases: this is the first repo primary on a ransomware family whose defining trait is **detection-evasion-by-omission** (no rename / no extension). It contrasts with the destructive-impact cases already in the diary — `2026-05-31_BlackShadow-AbabilOfMinab-Recovery-Layer-Destruction` (recovery-layer wipe) and `2026-05-01_VECT-2.0-RaaS` / `2026-05-05_Akira-SonicWall-CVE-2024-40766` / `2026-05-12_Qilin-EDR-Killer-msimg32` (extension-appending encryptors) — all of which announce themselves on disk. Aur0ra deliberately does not, which is the pedagogical hook.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial access | T1566.001, T1091 | Phishing attachment (macro doc / JS / PDF) per pcrisk; Aur0ra also enumerates the USB bus, consistent with removable-media spread (T1091 in CYFIRMA mapping) |
| Execution + anti-analysis | T1059, T1497.001, T1564.003, T1027.002, T1055 | x64 PE runs sandbox/VM/debugger checks, hidden window, software packing; process injection observed |
| Privilege escalation | T1134, T1546.011, T1548 | Access-token manipulation, application shimming, abuse of elevation control |
| Discovery | T1012, T1057, T1082, T1120, T1135 | Registry, process, system-info, peripheral (USB) and network-share enumeration |
| Collection + claimed exfil | T1560, T1071, T1090.003 | Archives collected data; claims exfiltration; victim contact funneled through Tor |
| Inhibit recovery | T1490 | `vssadmin Delete Shadows /all /quiet` and `wmic shadowcopy delete /nointeractive` |
| Impact | T1486 | In-place encryption — **no rename, no extension**; drops `!!!README!!!DO_NOT_DELETE.txt` |

![Aur0ra kill chain](./kill_chain.svg)

The diagram is a single-lane vertical timeline (template C): the victim Windows host walks top-to-bottom from delivery through anti-analysis, discovery, claimed exfiltration, and the two critical red stages — recovery inhibition and the silent in-place encryption that ends with the Tor/DLS extortion ask. The two red badges are the highest-fidelity detection anchors: shadow-copy deletion commands (pre-encryption) and the ransom-note write (encryption complete). Because nothing on disk is renamed, the note write and the VSS deletion are the loudest signals the family emits.

## Stage-by-stage detail

### Initial access — phishing attachment / removable media (T1566.001, T1091)

pcrisk attributes delivery to the commodity ransomware vectors: phishing emails carrying macro-enabled Office documents, JavaScript, archives with executables, or weaponised PDFs, plus pirated software, malvertising and fake update prompts. CYFIRMA's ATT&CK mapping additionally lists Replication Through Removable Media (T1091), which is consistent with the sample's observed enumeration of the USB bus during execution. There is no public evidence of exploitation of a specific CVE for initial access.

### Execution and anti-analysis (T1059, T1497.001, T1564.003, T1027.002, T1055)

The sample is a 64-bit Windows PE (AV family label `Win64/Filecoder.Aur0ra.A`). On execution it performs environment-awareness checks designed to determine whether it is running under a sandbox, virtual machine, or debugger — looking for analysis-tool processes/drivers/artifacts and timing inconsistencies — and modifies behaviour (pausing, exiting, or withholding payload actions) when monitoring is suspected (T1497.001). CYFIRMA's mapping also records hidden-window execution (T1564.003), software packing (T1027.002), and process injection (T1055). Treat the binary as packed and anti-analysis-aware: dynamic detonation in an instrumented sandbox may not reach the encryption stage.

### Privilege escalation (T1134, T1546.011, T1548)

CYFIRMA maps access-token manipulation (T1134), event-triggered execution via application shimming (T1546.011), and abuse of an elevation-control mechanism (T1548). These are pre-impact steps to obtain the rights needed to delete shadow copies and to encrypt files across the system.

### Discovery (T1012, T1057, T1082, T1120, T1135)

Before encrypting, Aur0ra profiles the host: queries the registry (T1012), enumerates running processes (T1057), gathers system information (T1082), enumerates connected peripherals via the USB bus (T1120), and discovers network shares (T1135). The peripheral and share enumeration is what lets an in-place encryptor reach mapped drives and removable media as well as local files.

### Collection and claimed exfiltration (T1560, T1071, T1090.003)

The ransom note asserts that "confidential information files" were downloaded prior to encryption — the data-theft half of double extortion. CYFIRMA maps Archive Collected Data (T1560) and Application Layer Protocol / Proxy (T1071, T1090) for the staging and egress; all post-compromise victim communication is funneled through a Tor (.onion) negotiation portal (T1090.003, multi-hop proxy). No exfiltration domain or volume is published, so the exfil is treated as *claimed* — defenders should still hunt for archive creation and large outbound transfers preceding the encryption window.

### Inhibit recovery (T1490) — critical

```text
vssadmin.exe Delete Shadows /all /quiet
wmic shadowcopy delete /nointeractive
```

Aur0ra deletes Volume Shadow Copies to block local restore (system restore points, previous versions, and shadow-backed backups). This is the single most reliable pre-encryption tell across the whole family and across commodity ransomware in general — it is loud, high-fidelity, and happens *before* the encryption completes, which is the window in which a response can still save data. ATT&CK: T1490 Inhibit System Recovery.

### Impact — in-place encryption, no rename, no extension (T1486) — critical

```text
Original:  C:\Users\<user>\Documents\1.jpg   (openable)
After:     C:\Users\<user>\Documents\1.jpg   (same name, same extension, NOT openable)
Note:      <every affected directory>\!!!README!!!DO_NOT_DELETE.txt
```

Aur0ra encrypts file contents while leaving the filename and extension untouched (verified on both the CYFIRMA and pcrisk test machines with the `1.jpg` example). When encryption finishes it drops a single text note, `!!!README!!!DO_NOT_DELETE.txt`, whose body reads (per pcrisk):

```text
We have downloaded confidential information files.
Your files are encrypted. Contact us via tor browser at
<onion link>
Your access key: <key>
```

The note contains only a Tor link and a per-victim access key — no ransom amount, deadline, or free-test-decryption offer. ATT&CK: T1486 Data Encrypted for Impact. The defensive consequence is covered in detail under Detection strategy: because the on-disk name does not change, any control that keys on extension changes or on "file was renamed" will miss the encryption entirely; the note write and the content-modification pattern are the signals that remain.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| Aur0ra encryptor | `81ca5fc6b55accdbc44266d66bd72c7c4152a75b215593adc433d51250054333` | C/C++ (x64 PE) | packed (T1027.002) | VirusTotal-submitted sample referenced by pcrisk; AV family `Win64/Filecoder.Aur0ra.A` |
| Remus Stealer (secondary) | `48385492b6518cb2f3adcfd4a49c065ba960bdc617817068bd5faeb493d3f2db` | x64 PE | runtime-decoded | Separate malware in the same CYFIRMA report; see Secondary findings — **not** part of the Aur0ra chain |

Aur0ra: no public unpacking write-up, cipher identification, or key-management analysis exists yet; the encryption algorithm (symmetric vs. asymmetric) is undocumented and no free decryptor is known. What is verifiable from public reporting is the *behaviour*: packed x64 PE, anti-analysis checks, in-place content encryption with no rename, VSS deletion, and the fixed note filename. The hash above is included at medium confidence because it is a single VT-linked sample rather than a vendor-confirmed campaign indicator; rotate-tolerant behavioural detection (below) is preferred over hash matching.

## Detection strategy

### Telemetry that matters

- **Sysmon EID 1** (process creation): `vssadmin.exe`, `wmic.exe`, `wbadmin.exe`, `bcdedit.exe` with recovery-destruction arguments; peripheral/share discovery via `wmic`/`net`.
- **Sysmon EID 11** (file create): creation of `!!!README!!!DO_NOT_DELETE.txt`; bursts of file modifications by a single non-system process.
- **Windows Security 4688** (process creation with command line) as a Sysmon fallback for the VSS/wbadmin/bcdedit commands.
- **Defender XDR**: `DeviceProcessEvents` (recovery deletion, discovery), `DeviceFileEvents` (note write, mass modification).
- **Sentinel**: `SecurityEvent` (4688) for the same command-line anchors where Sysmon is absent.
- **EDR file I/O / canary telemetry**: per-process counts of `FileModified` events — the only generic way to see an in-place encryptor that never triggers a rename event.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [`sigma/01_aur0ra_inhibit_recovery_vss.yml`](./sigma/01_aur0ra_inhibit_recovery_vss.yml) | process_creation — VSS / wbadmin / bcdedit recovery destruction (T1490) |
| Sigma | [`sigma/02_aur0ra_ransom_note_fileevent.yml`](./sigma/02_aur0ra_ransom_note_fileevent.yml) | file_event — write of `!!!README!!!DO_NOT_DELETE.txt` (T1486) |
| Sigma | [`sigma/03_aur0ra_removable_share_discovery.yml`](./sigma/03_aur0ra_removable_share_discovery.yml) | process_creation — removable-media + share enumeration burst (T1120/T1135) |
| KQL | [`kql/k1_aur0ra_inhibit_recovery.kql`](./kql/k1_aur0ra_inhibit_recovery.kql) | DeviceProcessEvents — recovery-destruction command lines |
| KQL | [`kql/k2_aur0ra_ransom_note.kql`](./kql/k2_aur0ra_ransom_note.kql) | DeviceFileEvents — ransom-note filename across the fleet |
| KQL | [`kql/k3_aur0ra_discovery_burst.kql`](./kql/k3_aur0ra_discovery_burst.kql) | DeviceProcessEvents — peripheral/share discovery |
| KQL | [`kql/k4_aur0ra_mass_inplace_modify.kql`](./kql/k4_aur0ra_mass_inplace_modify.kql) | DeviceFileEvents — many file modifications by one non-system process (no rename) |
| YARA | [`yara/aur0ra_filecoder.yar`](./yara/aur0ra_filecoder.yar) | ransom-note artifact, embedded recovery-destruction strings, Remus Stealer strings |
| Suricata | [`suricata/aur0ra_secondary_c2.rules`](./suricata/aur0ra_secondary_c2.rules) | Remus Stealer C2 (`cheapoca.biz`) + Tor-egress policy note (Aur0ra itself is Tor-only) |

No SPL is shipped (retired repo-wide 2026-05-11). Convert any Sigma rule with `sigma convert -t splunk -p sysmon <rule>.yml`.

### Threat hunting hypotheses

- **H1 — Recovery inhibition precedes encryption.** A host runs `vssadmin Delete Shadows` / `wmic shadowcopy delete` / `wbadmin delete` / `bcdedit /set ... recoveryenabled no`, then shows a burst of file modifications within minutes. See [`hunts/peak_h1_inhibit_recovery_then_encrypt.md`](./hunts/peak_h1_inhibit_recovery_then_encrypt.md).
- **H2 — In-place encryption with no rename.** A single non-system process modifies a large number of files across local and mapped drives without any corresponding rename/extension-change events, optionally followed by a `!!!README!!!DO_NOT_DELETE.txt` write. See [`hunts/peak_h2_inplace_no_rename_canary.md`](./hunts/peak_h2_inplace_no_rename_canary.md).
- **H3 — Pre-encryption peripheral and share enumeration.** Sandbox-aware binary enumerates the USB bus and network shares shortly before impact. See [`hunts/peak_h3_removable_share_recon.md`](./hunts/peak_h3_removable_share_recon.md).

## Incident response playbook

### First 60 minutes (triage)

1. **Isolate** the affected host(s) from the network immediately (disable NIC / quarantine in EDR) to stop reach into mapped drives, network shares, and removable media — Aur0ra enumerates all three.
2. **Do not reboot or shut down** the host — anti-analysis filecoders may resume or complete encryption on restart, and volatile artifacts (injected process, keys in memory) are lost.
3. **Confirm scope by the note, not the extension** — search the fleet for `!!!README!!!DO_NOT_DELETE.txt`; do not search for a changed extension (there is none).
4. **Check Volume Shadow Copy state** (`vssadmin list shadows`) on affected and adjacent hosts; if shadows already deleted, treat impact as confirmed.
5. **Unplug and inventory removable media and identify mapped/network shares** reachable from the host.
6. **Capture memory** before any containment that ends the process, to preserve potential keys and the unpacked image.
7. **Preserve** the binary, the note, and a sample encrypted file for analysis / ID-Ransomware / No More Ransom submission.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Process creation logs | Sysmon EID 1 / Security 4688 | EvtxECmd / KAPE | VSS deletion + discovery command lines |
| File creation logs | Sysmon EID 11 | EvtxECmd | Ransom-note write, modification burst |
| Ransom note | `**\!!!README!!!DO_NOT_DELETE.txt` | file copy | Scope confirmation + access key for IR record |
| Suspect binary | wherever dropped (often `%TEMP%`, user dirs) | memory dump / disk image | Hashing, unpacking, family confirmation |
| Memory image | live RAM | WinPMEM / DumpIt | Recover keys / unpacked payload before they are lost |
| VSS state | system | `vssadmin list shadows` | Determine if local recovery is still possible |
| Encrypted sample | any affected file | file copy | ID-Ransomware / decryptor feasibility check |

### IR queries and commands

```powershell
# Fleet sweep for the ransom note (the reliable scope signal — there is no extension to grep)
Get-ChildItem -Path C:\,D:\ -Recurse -Force -ErrorAction SilentlyContinue `
  -Filter '!!!README!!!DO_NOT_DELETE.txt' | Select-Object FullName,LastWriteTime

# Shadow copy state (was recovery already inhibited?)
vssadmin list shadows

# Recent VSS / recovery-tampering process events (Sysmon EID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
  Where-Object { $_.Message -match 'vssadmin|shadowcopy|wbadmin|bcdedit' } |
  Select-Object TimeCreated,Message -First 50
```

```kql
// Defender XDR: recovery destruction in the last 24h, fleet-wide
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("Delete Shadows", "shadowcopy delete", "wbadmin delete", "recoveryenabled no")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### Containment, eradication, recovery

- **Exit criteria:** no host shows new `!!!README!!!DO_NOT_DELETE.txt` writes or new modification bursts for a sustained window; the binary and any persistence (shim database, scheduled task) are removed; credentials used during the intrusion are rotated.
- **What NOT to do:** do not pay (no decryptor is guaranteed and the note offers no test decryption); do not rely on local shadow copies (deleted); do not restore from a backup that was reachable from the infected host without first confirming the backup itself is clean; do not assume "files look normal" means safety — names are unchanged by design.
- **Eradicate:** remove the binary and any application-shim / token-manipulation persistence; rebuild from known-good media for hosts where the unpacked payload or injection scope is uncertain.
- **Recover:** restore from offline/immutable backups created before the encryption window. Submit a sample + note to ID-Ransomware and check No More Ransom for a decryptor (none known at time of writing).

### Recovery validation

Confirm restored files open correctly (content, not just filename), re-enable and re-baseline Volume Shadow Copies, verify backups are immutable/offline and tested against an adversary-with-domain-admin scenario, and monitor restored hosts for re-encryption (modification burst) for at least one business cycle.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | `81ca5fc6b55accdbc44266d66bd72c7c4152a75b215593adc433d51250054333` | Aur0ra encryptor sample (VirusTotal-linked) | medium | pcrisk / VirusTotal |
| path | `!!!README!!!DO_NOT_DELETE.txt` | Ransom note filename (dropped per affected directory) | high | CYFIRMA / pcrisk |
| string | `We have downloaded confidential information files.` | First line of ransom note body | high | pcrisk |
| string | `Your access key:` | Ransom note per-victim key field | high | pcrisk |
| string | `vssadmin Delete Shadows /all /quiet` | Pre-encryption recovery inhibition | high | CYFIRMA |
| string | `wmic shadowcopy delete /nointeractive` | Pre-encryption recovery inhibition | high | CYFIRMA |
| note | No file rename / no extension added on encryption | Defeats extension-watch and canary-rename detection | high | CYFIRMA / pcrisk |
| note | AV labels: ESET `Win64/Filecoder.Aur0ra.A`; MS `Ransom:Win32/Genasom!rfn` | Family confirmation across engines | high | pcrisk / VirusTotal |
| sha256 | `48385492b6518cb2f3adcfd4a49c065ba960bdc617817068bd5faeb493d3f2db` | Remus Stealer sample (SECONDARY — not Aur0ra) | medium | CYFIRMA |
| domain | `cheapoca[.]biz` | Remus Stealer C2 (SECONDARY) | medium | CYFIRMA |
| ipv4 | `162.159.36.2` | Observed UDP/53 from Remus host; Cloudflare resolver range — likely benign DNS, listed for completeness | low | CYFIRMA |
| regkey | `{4590F811-1D3A-11D0-891F-00AA004B2E24}` | COM Elevation Moniker CLSID abused by Remus Stealer (SECONDARY) | medium | CYFIRMA |

Full list in [`iocs.csv`](./iocs.csv). The Remus Stealer rows are a *separate* malware shipped in the same CYFIRMA weekly report and are clearly marked SECONDARY; they are not part of the Aur0ra chain.

## Secondary findings

- **Remus Stealer (info-stealer, same CYFIRMA report).** A staged x64 stealer that pivots on WMI (`wmiprvse.exe`/`wmiadap.exe`, `ROOT\CIMV2`, `Win32_OperatingSystem`/`Win32_VideoController`) for host/sandbox fingerprinting, then escalates via the COM Elevation Moniker CLSID `{4590F811-1D3A-11D0-891F-00AA004B2E24}`, touches `amsi.dll` and `sysmain.sdb`, and beacons to `cheapoca.biz` on non-standard ports (500, 5003–5007). It is unrelated to Aur0ra but is covered by one YARA rule and the Suricata file here because it travelled in the same intel bundle and has concrete IOCs.
- **Detection-by-omission is a trend, not a one-off.** Aur0ra is one of several 2026 commodity families catalogued in the same window that skip the rename step; the design choice specifically targets the cheapest endpoint heuristics (extension allow/deny lists, FSRM file-screen rename triggers, canary "if renamed then alert" rules). Detection must move to recovery-inhibition and per-process modification-rate signals.
- **Tor-only negotiation with a bare access key.** The note omits ransom amount, deadline, and test decryption — a minimalist operating model that gives responders almost nothing to triage on the network side and pushes all detection value back onto the host (VSS deletion, note write, modification burst).

## Pedagogical anchors

- **If your ransomware detection keys on the file extension, it is blind to Aur0ra.** Encryption is an action on file *content*; the extension is cosmetic. Detect impact by recovery inhibition (VSS/wbadmin/bcdedit) and by per-process file-modification rate, never by a new suffix.
- **Canary/honeypot files must alert on content change, not rename.** A no-rename encryptor will modify a canary in place; a rule that fires only on rename or move will stay silent. Watch the canary's hash/last-write, not its name.
- **The loudest, earliest, highest-fidelity ransomware signal is shadow-copy deletion** — it happens before encryption finishes and is rarely benign on a workstation. Make it a paging alert, not a daily-digest line.
- **Scope by artifact, not by extension.** During IR, sweep for the note filename `!!!README!!!DO_NOT_DELETE.txt`; a "find files with extension X" sweep returns nothing here and creates a false sense of containment.
- **One hash, one VT submission ≠ a campaign indicator.** The Aur0ra sample hash is useful but brittle; behavioural rules survive repacks and the next sample.

## What's in this folder

| File | Purpose |
|---|---|
| [`README.md`](./README.md) | This analysis. |
| [`kill_chain.svg`](./kill_chain.svg) | Single-lane (template C) kill-chain diagram with the two critical-stage anchors. |
| [`sigma/01_aur0ra_inhibit_recovery_vss.yml`](./sigma/01_aur0ra_inhibit_recovery_vss.yml) | Sigma: VSS/wbadmin/bcdedit recovery destruction (T1490). |
| [`sigma/02_aur0ra_ransom_note_fileevent.yml`](./sigma/02_aur0ra_ransom_note_fileevent.yml) | Sigma: ransom-note file write (T1486). |
| [`sigma/03_aur0ra_removable_share_discovery.yml`](./sigma/03_aur0ra_removable_share_discovery.yml) | Sigma: removable-media + share enumeration burst (T1120/T1135). |
| [`kql/k1_aur0ra_inhibit_recovery.kql`](./kql/k1_aur0ra_inhibit_recovery.kql) | KQL: recovery-destruction command lines. |
| [`kql/k2_aur0ra_ransom_note.kql`](./kql/k2_aur0ra_ransom_note.kql) | KQL: ransom-note filename sweep. |
| [`kql/k3_aur0ra_discovery_burst.kql`](./kql/k3_aur0ra_discovery_burst.kql) | KQL: peripheral/share discovery. |
| [`kql/k4_aur0ra_mass_inplace_modify.kql`](./kql/k4_aur0ra_mass_inplace_modify.kql) | KQL: per-process mass file modification (no rename). |
| [`yara/aur0ra_filecoder.yar`](./yara/aur0ra_filecoder.yar) | YARA: ransom note, embedded recovery-destruction strings, Remus Stealer strings. |
| [`suricata/aur0ra_secondary_c2.rules`](./suricata/aur0ra_secondary_c2.rules) | Suricata: Remus Stealer C2 + Tor-egress policy note. |
| [`hunts/peak_h1_inhibit_recovery_then_encrypt.md`](./hunts/peak_h1_inhibit_recovery_then_encrypt.md) | PEAK hunt H1. |
| [`hunts/peak_h2_inplace_no_rename_canary.md`](./hunts/peak_h2_inplace_no_rename_canary.md) | PEAK hunt H2. |
| [`hunts/peak_h3_removable_share_recon.md`](./hunts/peak_h3_removable_share_recon.md) | PEAK hunt H3. |
| [`iocs.csv`](./iocs.csv) | Machine-readable IOCs (Aur0ra primary + Remus secondary, marked). |

## Sources

- [CYFIRMA — Weekly Intelligence Report, 22 May 2026 (Aur0ra ransomware + Remus Stealer)](https://www.cyfirma.com/news/weekly-intelligence-report-22-may-2026/)
- [pcrisk — Aur0ra Ransomware (decryption, removal, recovery; VT-analysed)](https://www.pcrisk.com/removal-guides/35259-aur0ra-ransomware)
- [Tech Jacks Solutions — Aur0ra Ransomware: Stealthy Encryption and Double-Extortion](https://techjacksolutions.com/scc-intel/aur0ra-ransomware-stealthy-encryption-and-double-extortion-strain/)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK — T1497.001 Virtualization/Sandbox Evasion: System Checks](https://attack.mitre.org/techniques/T1497/001/)
- [No More Ransom — decryptor search](https://www.nomoreransom.org/en/decryption-tools.html)
