---
date: 2026-06-30
title: "Dire Wolf: a Golang double-extortion ransomware that kills the recovery story before it encrypts"
clusters: ["Dire Wolf (DireWolf) ransomware group"]
cluster_country: "Unattributed e-crime; financially motivated; victim concentration in SE Asia + APAC"
techniques_enterprise: [T1486, T1490, T1489, T1562.001, T1070.001, T1070.004, T1047, T1059.003, T1027.002, T1529, T1480, T1657, T1083, T1003.001]
techniques_ics: []
platforms: [windows]
sectors: [manufacturing, technology, finance, healthcare, logistics, automotive]
category: ransomware
---

# Dire Wolf: a Golang double-extortion ransomware that kills the recovery story before it encrypts

## TL;DR

Dire Wolf is a financially motivated double-extortion ransomware crew that surfaced in May 2025 and is still actively posting victims through mid-2026 (Did Asia, an automotive-parts firm in Thailand, on 2026-06-12; CYFIRMA re-profiled the family in its 2026-06-26 weekly intelligence report, which is the reason it lands today). The payload is a Go binary, UPX-packed, that takes a `-d <dir>` target argument, fans out a worker pool of 8x the logical-CPU count, and uses Curve25519 key exchange + ChaCha20 stream encryption with SHA-256 key/nonce derivation, appending a `.direwolf` extension. Before it encrypts anything it executes a textbook recovery-denial sequence — `vssadmin delete shadows`, `wbadmin delete backup`, `bcdedit /set {default} recoveryenabled No`, a WMI-driven loop that repeatedly kills the `eventlog` service, and `wevtutil cl` against the four core logs — then forces a reboot with `shutdown -r -f -t 10` and self-deletes via a `timeout`/`del` chain. Victims span manufacturing, technology, finance, healthcare and logistics, mostly in Singapore, Thailand, the Philippines and Taiwan, with ransom demands around USD 500,000 negotiated over qTox. The durable lesson for a crime-economy day: the recovery-inhibition burst happens *before* the file rename, so the earliest reliable tell is behavioral, not extension-based.

## Attribution and confidence

Cluster: **Dire Wolf** (also written **DireWolf**), an unattributed, self-branded ransomware-as-extortion operation. First leak-site postings 2025-05-26 (six victims at once). Public technical analysis: **Trustwave SpiderLabs** (first deep-dive, 2025-06), **AhnLab ASEC** (execution-flow analysis, 2025-09-01), **Protos Labs** (TTP/IOC enrichment, 2025-08-28), **Singapore CSA** advisory AL-2025-082 and **ThaiCERT**. Ongoing tracking: **CYFIRMA** weekly intelligence (2026-06-26), **SOCRadar**, **ransomware.live**.

Attribution confidence: **low (actor identity) / high (family + mechanism)**. The group claims a pure-profit motive and communicates over Tox; no nation-state or named e-crime brand overlap has been established. The malware family itself is identified with high confidence from sample hashes, the hard-coded `Global\direwolfAppMutex` mutex, the `C:\runfinish.exe` completion marker, the `HowToRecoveryFiles.txt` note, and the `.direwolf` extension, which co-occur across independent vendor analyses.

| Overlap candidate | Basis | Assessment |
|---|---|---|
| Generic Golang RaaS builders | Go + UPX, ChaCha20/Curve25519, intermittent encryption | Common toolkit pattern, not a shared-codebase link |
| Infostealer log markets (AgentTesla / Dridex referenced by Protos) | Credential access feeding initial access | Plausible IAB-style entry; unconfirmed for any single intrusion |
| Mercenary / hacktivist crews | Claimed (unconfirmed) triple-extortion DDoS option | No evidence of shared infrastructure |

Genealogy vs previous repo cases: this is the **first Dire Wolf case** and the repo's first primary anchored on a Go-based double-extortion filecoder. It complements but does not overlap `2026-06-02_Aur0ra-NoRename-InPlace-Ransomware` (in-place, no-rename Windows filecoder), `2026-05-01_VECT-2.0-RaaS` (ransomware/wiper, ChaCha20), `2026-06-09_Kyber-Dual-ESXi-Windows-Backup-Hypervisor-Ransomware` (ESXi/Windows dual payload), and `2026-06-16_Qilin-CheckPoint-IKEv1` (Qilin affiliate, edge-VPN entry). The shared theme across Aur0ra/VECT/Kyber and Dire Wolf is that recovery-inhibition and note-write are the durable anchors; the distinguishing feature here is the WMI-driven `eventlog`-kill loop and the forced-reboot + self-delete finale.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial access (suspected) | T1190 / T1133 / T1078 / T1566 | Vendor-suspected entry via VPN-appliance exploitation, valid/stolen accounts, infostealer logs or phishing; not conclusively documented per intrusion |
| Credential access + lateral (suspected) | T1003.001, T1047, T1059.001 | Mimikatz-class dumping; living-off-the-land with PowerShell/WMI/PsExec |
| Execution guardrail | T1480 | `Global\direwolfAppMutex` mutex + `C:\runfinish.exe` marker check; aborts + self-deletes if already run |
| Defense evasion — kill services/processes | T1489, T1562.001 | Terminates backup (Veeam, Veritas BackupExec), DB (MSSQL, Oracle), mail (Exchange), virtualization (VMware) and security (Symantec, Sophos) services/processes |
| Inhibit recovery | T1490 | `vssadmin delete shadows /all /quiet`; `wbadmin delete backup -keepVersions:0 -quiet`; `bcdedit /set {default} recoveryenabled No` + `bootstatuspolicy ignoreallfailures` |
| Indicator removal — logs | T1070.001, T1047 | WMI query for `eventlog` PID then `taskkill` in a repeating loop; `wevtutil cl` on Application/System/Security/Setup |
| Impact — encryption | T1486 | Curve25519 + ChaCha20, SHA-256 derived key/nonce, intermittent (>1 MB = first 1 MB only), `.direwolf` extension, `HowToRecoveryFiles.txt` note |
| Post-impact | T1529, T1070.004 | `C:\runfinish.exe` marker write; `cmd /c start shutdown -r -f -t 10`; `timeout /T 3` + `del` self-deletion |
| Extortion | T1657, T1041 | Tor leak site + qTox negotiation; per-victim `roomID`/`username` embedded in note; ~USD 500k demand |

![Dire Wolf kill chain](./kill_chain.svg)

The diagram is two-lane. The left lane is the victim Windows host walking from suspected initial access through the pre-encryption recovery-denial burst (the two red/critical stages) to encryption and the forced-reboot/self-delete finale. The right lane is the operator's build and extortion machinery: the mutex/marker guardrail, the Go/UPX build with its 8x-CPU worker pool, the service/process kill lists, the leak-site + qTox negotiation channel, and the `tor-browser[.]io` social-engineering infrastructure. The durable detection anchors — recovery-inhibition burst, the WMI `eventlog`-kill loop, and the `runfinish.exe` + forced-reboot + self-delete chain — are all host-behavioral and survive hash and onion rotation.

## Stage-by-stage detail

### Stage 1 — Initial access (suspected)

No single intrusion has a publicly confirmed entry vector. Vendors (Protos Labs, CSA) assess the likely vectors as VPN-appliance exploitation (Ivanti Connect Secure named as an example class), valid/stolen credentials from infostealer log markets, and phishing. Treat these as hypotheses, not confirmed IOCs.

```
# Suspected, not confirmed per-intrusion:
#   T1190  exploitation of internet-facing VPN/appliance
#   T1078  valid accounts from infostealer logs
#   T1566  phishing with malicious attachment/link
```

MITRE: T1190 Exploit Public-Facing Application; T1133 External Remote Services; T1078 Valid Accounts; T1566 Phishing (all suspected).

### Stage 2 — Credential access and lateral movement (suspected)

Protos Labs references Mimikatz-class credential dumping and living-off-the-land lateral movement (PowerShell, WMI, PsExec). These align with the broad ransomware playbook but are not sample-confirmed for Dire Wolf specifically.

MITRE: T1003.001 OS Credential Dumping: LSASS Memory; T1047 WMI; T1059.001 PowerShell; T1021.002 SMB/Windows Admin Shares (suspected).

### Stage 3 — Execution guardrail (mutex + completion marker)

On launch the Go binary parses arguments (`-d <dir>` to scope a target directory, `-h` for help), then performs a protection check: it opens the system-wide mutex `Global\direwolfAppMutex` and checks for the completion marker `C:\runfinish.exe`. If either already exists the process logs the event, calls its self-deletion routine, and exits — preventing double-encryption.

```
mutex:  Global\direwolfAppMutex
marker: C:\runfinish.exe   (empty file, written post-encryption)
```

MITRE: T1480 Execution Guardrails.

### Stage 4 — Kill backup / DB / security services and processes

Before encrypting, Dire Wolf terminates processes and services that would otherwise hold file handles, retain recoverable copies, or detect the attack. ASEC documents targets including databases (`sqlservr.exe`, Oracle), mail (`Exchange`), virtualization (`VMware`, `vss.exe`), backup (Veeam `VeeamTransportSvc`, Veritas `BackupExecJobEngine`) and security suites (Symantec, Sophos), plus service names such as `SQLSERVERAGENT`, `MSExchangeIS`, `wuauserv` and `BackupExecJobEngine`.

```
# representative process targets (non-exhaustive):
sqlservr.exe  vss.exe  memtas.exe  tomcat6.exe  onenote.exe  outlook.exe
# representative service targets:
BackupExecJobEngine  SQLSERVERAGENT  VeeamTransportSvc  MSExchangeIS  wuauserv
```

MITRE: T1489 Service Stop; T1562.001 Impair Defenses: Disable or Modify Tools.

### Stage 5 — Inhibit system recovery (critical)

This is the highest-fidelity pre-encryption window. Dire Wolf runs the classic recovery-denial set from the command shell:

```
vssadmin delete shadows /all /quiet
wbadmin stop job -quiet
wbadmin delete backup -keepVersions:0 -quiet
wbadmin delete systemstatebackup
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

The `bcdedit bootstatuspolicy ignoreallfailures` line prevents WinRE from being entered on a failed boot, compounding the shadow-copy and backup deletion. Because these commands precede the rename, a recovery-inhibition rule fires before a single byte of the user's data carries the `.direwolf` extension.

MITRE: T1490 Inhibit System Recovery.

### Stage 6 — Destroy event logs (WMI loop + wevtutil)

Dire Wolf does not merely clear logs once. It resolves the `eventlog` service PID with a WMI query, force-kills it, waits, and repeats in a loop, so even an auto-restarted service is re-killed and log collection stays blocked. It then clears the major channels with `wevtutil cl`.

```
Get-WmiObject -Class win32_service -Filter "name = 'eventlog'"  ->  taskkill /F /PID <pid>   (looped)
wevtutil cl Application
wevtutil cl System
wevtutil cl Security
wevtutil cl Setup
```

MITRE: T1070.001 Indicator Removal: Clear Windows Event Logs; T1047 WMI.

### Stage 7 — Encryption

A per-file random private key is generated and combined with the hard-coded Dire Wolf public key via Curve25519. The shared secret is hashed with SHA-256 to produce the ChaCha20 key, and the result is hashed again to derive the nonce. Files under 1 MB are fully encrypted; files over 1 MB have only the first 1 MB encrypted (intermittent encryption for speed). Traversal excludes OS/recovery-critical folders (`AppData`, `Windows`, `Program Files`, `$Recycle.Bin`, `System Volume Information`), boot files (`bootmgr`, `ntldr`, `NTUSER.DAT`), the note `HowToRecoveryFiles.txt`, and extensions `.exe/.dll/.sys/.drv/.iso/.img` so the host stays bootable enough to show the note. The worker pool is sized at 8x the logical-CPU count.

```
key exchange: Curve25519 (per-file ephemeral priv + hard-coded attacker pub)
cipher:       ChaCha20, key = SHA-256(shared), nonce = SHA-256(SHA-256(shared))
mode:         <1MB full ; >1MB first-1MB only (intermittent)
extension:    .direwolf
note:         HowToRecoveryFiles.txt  (per-folder; embeds roomID + username + qTox ID)
```

MITRE: T1486 Data Encrypted for Impact.

### Stage 8 — Forced reboot and self-deletion

After writing the `C:\runfinish.exe` marker the malware schedules a forced reboot and self-deletes asynchronously so the sample is gone before responders can pull it from disk:

```
cmd /c start shutdown -r -f -t 10
timeout /T 3  &&  del <self>          (spawned via a separate cmd.exe)
```

CYFIRMA's 2026-06-26 profile highlights a self-delete variant using `ping` as the delay primitive instead of `timeout` (a `ping -n N 127.0.0.1 > nul & del` pattern); both are sleep-then-delete chains and a detection should cover either delay tool. MITRE: T1529 System Shutdown/Reboot; T1070.004 Indicator Removal: File Deletion.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| Dire Wolf filecoder | 27d90611f005db3a25a4211cf8f69fb46097c6c374905d7207b30e87d296e1b3 | Go | UPX | Confirmed sample (Protos/Trustwave) |
| Dire Wolf filecoder | 8fdee53152ec985ffeeeda3d7a85852eb5c9902d2d480449421b4939b1904aad | Go | UPX | Additional confirmed binary |
| Dire Wolf (66/AV) | 00065b7aeaa41e3aa52cf94be0f63afdd92e04799935d612f2451bcf4b1fb704 | Go | UPX | runtime-modules, direct-cpu-clock-access tags |

Packer / anti-analysis: UPX over a Go binary frustrates trivial static triage; the Go runtime's goroutine fan-out (8x logical CPUs) also spikes CPU/disk and can be a coarse performance tell on a live host. Cipher: Curve25519 + ChaCha20 with double-SHA-256 derivation; intermittent encryption above 1 MB. There is no flaw in the crypto — recovery depends on backups that survive Stage 5, not on decryption. AhnLab additionally lists four MD5s for the family: `333fd9dd9d84b58c4eef84a8d07670dd`, `44da29144b151062bce633e9ce62de85`, `aa62b3905be9b49551a07bc16eaad2ff`, `bc6912c853be5907438b4978f6c49e43`; CYFIRMA (2026-06-26) lists MD5 `4924b945cfdc5bfece03f5140a546384` for a 2026 sample.

## Detection strategy

### Telemetry that matters

- Sysmon EID 1 (process creation) with full command line — the recovery-inhibition commands, the `taskkill`/WMI `eventlog` loop, `wevtutil cl`, `shutdown -r -f -t 10`, and the `timeout|ping ... & del` self-delete are all command-line visible.
- Sysmon EID 11 (file create) — `C:\runfinish.exe` marker, `HowToRecoveryFiles.txt` mass write, `.direwolf` rename churn.
- Defender XDR `DeviceProcessEvents`, `DeviceFileEvents`; Sentinel `SecurityEvent` (4688 with command line), `Event` (Sysmon).
- Windows Security 1102 / System 104 (log cleared) as a corroborating but late signal; the WMI `eventlog`-kill loop may suppress these, so do not rely on them alone.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/direwolf_inhibit_recovery_burst.yml | vssadmin/wbadmin/bcdedit recovery-denial command lines |
| Sigma | sigma/direwolf_eventlog_kill_and_clear.yml | WMI/taskkill against `eventlog` + `wevtutil cl` |
| Sigma | sigma/direwolf_marker_and_note_fileevent.yml | `C:\runfinish.exe` marker + `HowToRecoveryFiles.txt` write (file_event) |
| KQL | kql/direwolf_inhibit_recovery.kql | DeviceProcessEvents recovery-denial chain |
| KQL | kql/direwolf_eventlog_kill_loop.kql | DeviceProcessEvents WMI/taskkill `eventlog` + wevtutil |
| KQL | kql/direwolf_forced_reboot_selfdelete.kql | DeviceProcessEvents shutdown -r -f -t 10 + sleep/del |
| KQL | kql/direwolf_marker_note_fileevents.kql | DeviceFileEvents runfinish.exe + note + .direwolf |
| YARA | yara/direwolf.yar | Go+mutex+marker+note strings; recovery-command strings; note template |
| Suricata | suricata/direwolf.rules | tor-browser[.]io DNS/TLS/HTTP + onion address string (infra-decay) |

No SPL is shipped (retired repo-wide 2026-05-11); convert any Sigma with `sigma convert -t splunk -p sysmon <rule>.yml`.

### Threat hunting hypotheses

- **H1 (PEAK)** — A single non-administrative process spawns `vssadmin delete shadows`, `wbadmin delete`, and `bcdedit ... recoveryenabled No` within a short window. See `hunts/peak_h1_recovery_inhibition_burst.md`.
- **H2 (PEAK)** — The `eventlog` service is terminated more than once in a short interval (WMI PID lookup then `taskkill`), optionally followed by `wevtutil cl`. See `hunts/peak_h2_eventlog_kill_loop.md`.
- **H3 (PEAK)** — A burst of `HowToRecoveryFiles.txt` writes and `.direwolf` renames co-occurs with creation of `C:\runfinish.exe` and a `shutdown -r -f -t 10`. See `hunts/peak_h3_note_marker_reboot.md`.

## Incident response playbook

### First 60 minutes (triage)

1. Isolate hosts showing `.direwolf` files or `HowToRecoveryFiles.txt` at the network layer; do not power them off (self-delete + forced reboot already ran, but volatile artifacts may remain).
2. Identify the earliest host where `vssadmin/wbadmin/bcdedit` recovery-denial ran — that is closer to patient zero than the first-encrypted file server.
3. Check for `C:\runfinish.exe` on suspected hosts to confirm Dire Wolf and gauge completion.
4. Pull any surviving Sysmon/4688 command-line logs *before* the WMI `eventlog`-kill loop blanks them; query the SIEM, not just the host.
5. Freeze backups and verify immutability — Stage 5 specifically targets Veeam/Veritas; confirm offline/immutable copies are intact.
6. Hunt the estate for the recovery-inhibition burst and the `eventlog`-kill loop to scope spread.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Completion marker | C:\runfinish.exe | Triage script / EDR | Confirms Dire Wolf ran to completion |
| Ransom notes | **\HowToRecoveryFiles.txt | EDR / file collection | Embeds per-victim roomID + username + qTox ID |
| Process command lines | Sysmon EID 1 / Security 4688 | SIEM (pre-loop) | Recovery-denial + eventlog-kill + self-delete chain |
| Service/process kill evidence | System 7036 / EDR | EDR | Backup/DB/security termination order |
| Encrypted-file extension | *.direwolf | File listing | Scope and timeline of impact |
| Memory (if pre-reboot) | live RAM | WinPMEM/EDR | Go runtime, keys, decoded strings |

### IR queries and commands

```powershell
# Confirm Dire Wolf completion marker + scope ransom notes
Test-Path C:\runfinish.exe
Get-ChildItem -Path C:\ -Recurse -Filter HowToRecoveryFiles.txt -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime
# Inventory encrypted files
Get-ChildItem -Path C:\ -Recurse -Filter *.direwolf -ErrorAction SilentlyContinue |
  Measure-Object | Select-Object Count
```

```bash
# From collected EVTX / SIEM export: find the recovery-inhibition burst
grep -Ei 'vssadmin delete shadows|wbadmin delete backup|recoveryenabled No|bootstatuspolicy ignoreallfailures' process_creation.log
```

```kql
// Defender XDR: hosts that ran the recovery-denial chain in the last 14 days
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("delete shadows","wbadmin delete backup","recoveryenabled No","bootstatuspolicy ignoreallfailures")
| summarize cmds=make_set(ProcessCommandLine), n=dcount(ProcessCommandLine) by DeviceName, bin(Timestamp, 10m)
| where n >= 2
```

### Containment, eradication, recovery

- Containment exit criteria: no host in scope still spawns the recovery-denial chain or the `eventlog`-kill loop; affected accounts/credentials rotated (assume infostealer/Mimikatz exposure).
- Eradication: remove persistence/lateral footholds, rotate domain and service-account credentials, rebuild encrypted file servers from known-good media.
- Recovery: restore from offline/immutable backups validated against Stage 5 deletion; re-enable WinRE (`bcdedit /set {default} recoveryenabled Yes`).
- What NOT to do: do not pay expecting reliable decryption — the crypto is sound and recovery is a backup problem; do not reboot a still-live host hoping to "clear" it (reboot is exactly what the malware schedules); do not trust local event logs to scope the incident (the WMI loop blanks them) — use SIEM-forwarded telemetry.

### Recovery validation

Confirm shadow storage is re-provisioned and `recoveryenabled` is `Yes`; confirm backup services (Veeam/Veritas) and their schedules are restored and producing immutable copies; confirm no residual `runfinish.exe` markers or `.direwolf` files remain; re-enable and verify Windows event logging is collecting and forwarding.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | 27d90611f005db3a25a4211cf8f69fb46097c6c374905d7207b30e87d296e1b3 | Go/UPX Dire Wolf filecoder | high | Protos Labs 2025-08-28; Trustwave |
| sha256 | 8fdee53152ec985ffeeeda3d7a85852eb5c9902d2d480449421b4939b1904aad | Dire Wolf filecoder binary | high | Protos Labs 2025-08-28 |
| sha256 | 00065b7aeaa41e3aa52cf94be0f63afdd92e04799935d612f2451bcf4b1fb704 | Dire Wolf sample (66 AV detections) | high | Protos Labs 2025-08-28 |
| md5 | 333fd9dd9d84b58c4eef84a8d07670dd | Dire Wolf family hash | medium | AhnLab ASEC 2025-09-01 |
| md5 | 44da29144b151062bce633e9ce62de85 | Dire Wolf family hash | medium | AhnLab ASEC 2025-09-01 |
| md5 | 4924b945cfdc5bfece03f5140a546384 | Dire Wolf 2026 sample | medium | CYFIRMA 2026-06-26 |
| mutex | Global\direwolfAppMutex | Single-instance guard | high | AhnLab ASEC 2025-09-01 |
| path | C:\runfinish.exe | Completion marker (empty file) | high | AhnLab ASEC 2025-09-01 |
| path | HowToRecoveryFiles.txt | Ransom note (per folder) | high | AhnLab ASEC 2025-09-01 |
| string | .direwolf | Encrypted-file extension | high | AhnLab ASEC 2025-09-01 |
| domain | direwolfcdkv5whaz2spehizdg22jsuf5aeje4asmetpbt6ri4jnd4qd.onion | Tor leak/negotiation site | high | Protos Labs 2025-08-28 |
| domain | tor-browser[.]io | Malicious social-engineering / C2 infra | medium | Protos Labs 2025-08-28 |

Full machine-readable set including the AhnLab MD5s, subdomains and command-string notes in `iocs.csv`. No CVE is associated with this case (initial access is unconfirmed/varied), so there is no CISA KEV cross-reference and no `kev.md`. Network indicators (`tor-browser[.]io`, the onion host) decay — re-validate before blocking; the durable anchors are the host-behavioral rules.

## Secondary findings

- **Recovery-denial is the operator's first move, not a side effect.** Stage 5 (`vssadmin`/`wbadmin`/`bcdedit`) and the looping `eventlog` kill both run *before* any rename, so behavioral detection beats extension/canary rules by minutes — exactly the window in which an analyst can pull and forward command-line telemetry before the WMI loop blanks the local logs.
- **Self-erasing payload defeats post-reboot sampling.** The `shutdown -r -f -t 10` + `timeout|ping ... & del` finale removes the binary from disk; responders should expect to reconstruct the family from the marker file, notes and SIEM telemetry rather than from a recovered sample, and should preserve memory on any host caught pre-reboot.
- **Active in 2026 against APAC industry.** Continued leak-site postings through 2026 (Did Asia, 2026-06-12; PernelMedia earlier in 2026) and the 2026-06-26 CYFIRMA re-profile show this is not a 2025-only family; healthcare and finance are in scope alongside manufacturing/technology, which is why it fits the crime-economy rotation.

## Pedagogical anchors

- The earliest reliable ransomware tell is recovery inhibition, not file extension. Build the alert on `vssadmin/wbadmin/bcdedit` co-occurring from one parent, and you fire before the data is renamed.
- Treat local event logs as untrusted during a ransomware incident: a WMI-driven `eventlog`-kill loop can suppress 1102/104 entirely. Scope from SIEM-forwarded command-line telemetry, not the host.
- A forced reboot plus a sleep-then-`del` self-delete is an anti-forensics finale; preserve memory and the marker/note artifacts on any host caught before reboot, because the sample will be gone afterward.
- Sound crypto means recovery is a backups problem, not a decryption problem — and the backups must survive the kill-list (Veeam/Veritas) and the shadow-copy deletion, i.e. they must be offline/immutable.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (template A, ransomware accent). | [kill_chain.svg](./kill_chain.svg) |
| sigma/direwolf_inhibit_recovery_burst.yml | Sigma: recovery-denial command lines. | [view](./sigma/direwolf_inhibit_recovery_burst.yml) |
| sigma/direwolf_eventlog_kill_and_clear.yml | Sigma: eventlog kill loop + wevtutil cl. | [view](./sigma/direwolf_eventlog_kill_and_clear.yml) |
| sigma/direwolf_marker_and_note_fileevent.yml | Sigma: runfinish.exe marker + note write. | [view](./sigma/direwolf_marker_and_note_fileevent.yml) |
| kql/direwolf_inhibit_recovery.kql | KQL: recovery-denial chain (DeviceProcessEvents). | [view](./kql/direwolf_inhibit_recovery.kql) |
| kql/direwolf_eventlog_kill_loop.kql | KQL: eventlog termination + wevtutil. | [view](./kql/direwolf_eventlog_kill_loop.kql) |
| kql/direwolf_forced_reboot_selfdelete.kql | KQL: forced reboot + self-delete chain. | [view](./kql/direwolf_forced_reboot_selfdelete.kql) |
| kql/direwolf_marker_note_fileevents.kql | KQL: marker/note/.direwolf file events. | [view](./kql/direwolf_marker_note_fileevents.kql) |
| yara/direwolf.yar | YARA: Go+mutex+marker strings, recovery commands, note template. | [view](./yara/direwolf.yar) |
| suricata/direwolf.rules | Suricata: tor-browser[.]io + onion address (infra-decay). | [view](./suricata/direwolf.rules) |
| hunts/peak_h1_recovery_inhibition_burst.md | PEAK hunt: recovery-inhibition burst. | [view](./hunts/peak_h1_recovery_inhibition_burst.md) |
| hunts/peak_h2_eventlog_kill_loop.md | PEAK hunt: eventlog-kill loop. | [view](./hunts/peak_h2_eventlog_kill_loop.md) |
| hunts/peak_h3_note_marker_reboot.md | PEAK hunt: note/marker/reboot co-occurrence. | [view](./hunts/peak_h3_note_marker_reboot.md) |
| iocs.csv | Machine-readable IOCs. | [iocs.csv](./iocs.csv) |

## Sources

- [Trustwave SpiderLabs — Dire Wolf Strikes: New Ransomware Group Targeting Global Sectors](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/dire-wolf-strikes-new-ransomware-group-targeting-global-sectors/)
- [AhnLab ASEC — Dire Wolf Ransomware: Threat Combining Data Encryption and Leak Extortion](https://asec.ahnlab.com/en/89944/)
- [Protos Labs — Deep Dive Analysis into Dire Wolf Ransomware: TTPs and IOCs](https://www.protoslabs.io/resources/deep-dive-analysis-into-dire-wolf-ransomware-ttps-and-iocs)
- [Singapore CSA — Alert AL-2025-082 on Dire Wolf Ransomware](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-082/)
- [CSO Online — Singapore issues critical alert on Dire Wolf ransomware](https://www.csoonline.com/article/4042182/singapore-issues-critical-alert-on-dire-wolf-ransomware-targeting-global-tech-and-manufacturing-firms.html)
- [CYFIRMA — Weekly Intelligence Report, 26 Jun 2026](https://www.cyfirma.com/news/weekly-intelligence-report-26-jun-2026/)
- [SOCRadar — Dark Web Profile: Dire Wolf Ransomware](https://socradar.io/blog/dark-web-profile-dire-wolf-ransomware/)
- [Dark Reading — Dire Wolf Ransomware Comes Out Snarling, Bites Verticals](https://www.darkreading.com/threat-intelligence/dire-wolf-ransomware-manufacturing-technology)
