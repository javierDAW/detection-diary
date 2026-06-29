---
date: 2026-06-29
title: "CL-STA-1062 / TinyRCT: A Chinese-Speaking APT's Custom .NET Backdoor Against Southeast Asian Government and Energy"
clusters: ["CL-STA-1062"]
cluster_country: "China"
techniques_enterprise: [T1190, T1505.003, T1574.014, T1053.005, T1036.005, T1059.003, T1573.001, T1071.001, T1113, T1083, T1560.001, T1041, T1090, T1003.001, T1134.001, T1497.001, T1070.004, T1018]
techniques_ics: []
platforms: [windows]
sectors: [government, energy]
category: espionage
---

# CL-STA-1062 / TinyRCT: A Chinese-Speaking APT's Custom .NET Backdoor Against Southeast Asian Government and Energy

## TL;DR

Palo Alto Networks Unit 42 published (2026-06-26) a report on **CL-STA-1062**, a Chinese-speaking espionage cluster that overlaps with **UAT-7237** (Cisco Talos, Aug 2025) and has been active across East Asia since at least March 2022. From mid-2025 the group pivoted to **Southeast Asian government entities and state-owned critical energy infrastructure**, breaching at least ten organizations between October and December 2025. The campaign pairs a living-off-open-source toolkit (SoftEther VPN, VNT, Yuze, Mimikatz, JuicyPotato, fscan — frequently renamed `vmtools.exe`/`vmwared.exe`/`XDRAgent.exe`) with a bespoke, previously undocumented .NET backdoor named **TinyRCT** (`PerfWatson2.exe`) delivered through an **AppDomainManager-injection** loader. It matters today because TinyRCT is a fresh, low-visibility persistence implant with a clean self-destruct, and the operator's reliance on commodity tooling keeps attribution and cost low while the custom backdoor fills the long-haul-access gap.

## Attribution and confidence

**Cluster:** CL-STA-1062 (Unit 42). **Aliases / overlap:** UAT-7237 (Cisco Talos, Aug 2025, Taiwan web-hosting infrastructure). **Vendor / date:** Palo Alto Networks Unit 42, 2026-06-26. **Confidence:** medium.

Attribution is cluster-level and language-based rather than a named state group. Unit 42 assesses a **Chinese-speaking** actor: a **Simplified-Chinese string** sits inside TinyRCT's C2-response parsing routine, the toolset (SoftEther/VNT/Yuze/fscan) and tradecraft mirror China-nexus intrusion sets, and telemetry links the activity to long-running operations since March 2022. The strategic targeting of state-owned energy and government in Southeast Asia is consistent with state-aligned intelligence collection, but no specific PLA/MSS unit is named, so confidence is held at medium.

| Signal | Observation | Weight |
|---|---|---|
| Code language artifact | Simplified-Chinese string in TinyRCT C2 parser | medium |
| Toolset overlap | SoftEther VPN, VNT, Yuze, Mimikatz, fscan (China-nexus common) | medium |
| Cluster genealogy | Overlaps UAT-7237 (Talos, Taiwan web infra, Aug 2025) | medium |
| Victimology | SE Asia government + state-owned energy, strategic collection | medium |

**Genealogy with previous repo cases.** This is the repo's first case anchored on CL-STA-1062 / UAT-7237. It complements prior China-nexus entries — `2026-06-08_OP-512-China-IIS-WebShell-Framework` (web-shell-first initial access, same region of operations) and the Earth Estries / Salt Typhoon telecom espionage tracked under `byActor/earth-estries` — but the actor, the custom TinyRCT backdoor, and the AppDomainManager-injection loader are all new to the tree. It differs from the Vietnam-nexus `2026-06-15_OceanLotus-SPECTRALVIPER-FireAnt-SupplyChain` case despite the shared SE Asia theatre.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial access | T1190, T1505.003 | ASPX web shell dropped on a vulnerable public web application |
| Recon / discovery | T1018, T1083 | Internal scanning (fscan), traceroute mapping of a second gov entity |
| Privilege escalation | T1134.001 | JuicyPotato (SeImpersonate abuse) |
| Credential access | T1003.001 | Mimikatz |
| Tooling / tunneling | T1090, T1036.005 | SoftEther VPN, VNT, Yuze renamed vmtools.exe/vmwared.exe/XDRAgent.exe |
| Delivery | T1574.014 | chrome_setup.zip: signed exe + malicious .config + MyAppDomainManager.dll |
| Execution / download | T1059.003 | Loader fetches PerfWatson2.exe from 139.180.134[.]221 |
| Persistence | T1053.005 | Scheduled task GoogleUpdaterTaskSystem140.0.7272.0 (highest privileges) |
| C2 | T1071.001, T1573.001 | TinyRCT HTTP beacon to 45.32.113[.]172, AES-128-CBC, ~10s |
| Collection / exfil | T1113, T1560.001, T1041 | Screenshots, password-protected RAR, 40KB gzip+AES POST chunks |
| Anti-forensics | T1070.004 | choice.exe delay + self-delete; scheduled task removed |

![CL-STA-1062 TinyRCT kill chain](./kill_chain.svg)

The diagram tracks the victim Windows estate down the left lane (web-shell foothold through TinyRCT persistence and exfiltration) and the attacker infrastructure / operator tradecraft down the right lane (staging server, C2, renamed open-source tunnelers). The strongest detection anchors are **not** the rotating C2 IPs but the behavioral nodes: the AppDomainManager sideload, `PerfWatson2.exe` executing from `AppData`, and the `choice.exe`-timed self-delete.

## Stage-by-stage detail

### Initial access — ASPX web shell (T1190, T1505.003)

The operators gain a foothold by exploiting vulnerable public-facing web applications and dropping **ASPX web shells**, which they use for reconnaissance and tool delivery. Unit 42 did not attribute the entry to a single CVE; the durable signal is web-shell behavior on internet-facing IIS/.NET applications and anomalous child processes (e.g., `cmd.exe`) spawned by the web server worker.

### Reconnaissance and discovery (T1018, T1083)

In a September 2025 intrusion, after compromising one SE Asia government entity and exfiltrating data from an MS SQL server, the actor performed **network reconnaissance against a separate government entity in the same country**, using traceroute to map lateral-movement paths, and staged an entire directory of web-server **source code** for exfiltration. Internal scanning was performed with **fscan**.

```text
fscan  (SHA256 f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1)
```

### Privilege escalation and credential access (T1134.001, T1003.001)

Escalation relied on **JuicyPotato** (SeImpersonate / token-abuse against service accounts), and credential harvesting used **Mimikatz** — both off-the-shelf, keeping development cost and attribution low.

### Tooling and tunneling (T1090, T1036.005)

Persistent tunneling and lateral movement used **SoftEther VPN**, **VNT** (vnt-dev), and **Yuze** (a SOCKS5 proxy), commonly **masqueraded** as virtualization/EDR binaries:

```text
vmtools.exe / vmwared.exe / XDRAgent.exe   <- renamed open-source tunnelers
SoftEther VPN  SHA256 dce5df29bddff5a4ddaea5c4fec14da91f7b69063a6e1c45ed61e5da4fc6c87b
VNT            SHA256 9b481b69cd91b09fa7bae7428f646dd89473a4c03393e43da81fe756cde1c472
```

### Delivery — AppDomainManager injection (T1574.014)

TinyRCT arrives in **`chrome_setup.zip`**, containing a legitimately **signed** `chrome_setup.exe`, a malicious `chrome_setup.exe.config`, and a rogue `MyAppDomainManager.dll`. When the user runs the signed launcher, the .NET runtime reads the adjacent config and loads the attacker DLL **as the application-domain manager**, executing inside the trusted, signed process. The loader checks it is running from the user's **Downloads** folder before proceeding.

```text
chrome_setup.zip        SHA256 00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c
MyAppDomainManager.dll  SHA256 cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3
```

### Execution and download (T1059.003)

The loader contacts the staging server **`139.180.134[.]221`** to retrieve **`PerfWatson2.exe`** (TinyRCT), writes it to `%LOCALAPPDATA%`, and runs it. `PerfWatson2.exe` is a deliberate name collision with the genuine Visual Studio telemetry host (which lives under Program Files).

```text
PerfWatson2.exe (TinyRCT)  SHA256 4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384
install path               %LOCALAPPDATA%\PerfWatson2.exe
```

### Persistence (T1053.005)

The loader creates a **scheduled task** named **`GoogleUpdaterTaskSystem140.0.7272.0`** set to run at the **highest available privileges** on every user logon — masquerading as a Google updater task.

### C2 and the backdoor's capabilities (T1071.001, T1573.001)

TinyRCT is a lightweight C# RAT. On launch it enforces an **execution-location guard** (terminates unless under `%LOCALAPPDATA%`), fingerprints the host (username, machine name, OS, local IPs, path, PID, GUID), and registers with the C2. It then maintains a persistent **plain-HTTP** channel to **`45.32.113[.]172`**, encrypting payloads with **AES-128 in CBC mode** using the hardcoded key `ThisIsASecretKey87654321`, on a default **10-second** beacon: GET to poll for commands, POST to send data.

```text
C2          45.32.113[.]172  (HTTP; AES-128-CBC; key ThisIsASecretKey87654321; ~10s beacon)
capabilities: cmd.exe execution, dir/file enumeration, file read+exfil (40KB gzip+AES chunks),
              JPEG screenshot, file download from URL, config update, self-delete
```

### Collection, exfiltration and anti-forensics (T1113, T1560.001, T1041, T1070.004)

Data is staged as **password-protected RAR** archives; TinyRCT exfiltrates files in **40KB gzip-compressed, AES-encrypted chunks** via HTTP POST and can capture **JPEG screenshots**. On the wipe command it runs **`choice.exe`** to add a ~3-second delay (ensuring the process exits and releases its file handle) before **deleting its own executable** and **removing the persistence scheduled task**.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| TinyRCT (PerfWatson2.exe) | 4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384 | C# / .NET | none reported | AES-128-CBC HTTP C2; %LOCALAPPDATA% guard; Simplified-Chinese string in C2 parser |
| TinyRCT loader (MyAppDomainManager.dll) | cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3 | C# / .NET | none reported | AppDomainManager injection; Downloads-folder guard; downloads PerfWatson2.exe |
| Dropper (chrome_setup.zip) | 00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c | archive | n/a | signed launcher + malicious .config + rogue DLL |

Anti-analysis is environmental rather than packer-based: both the loader and the backdoor refuse to run outside their expected directory (Downloads / `%LOCALAPPDATA%`), which frustrates naive sandbox detonation. The cipher is symmetric AES-128-CBC with a static, recoverable key — useful for writing a decryptor for captured POST bodies in a lab.

## Detection strategy

### Telemetry that matters

- **Sysmon EID 7 (ImageLoad)** / Defender XDR `DeviceImageLoadEvents` — AppDomainManager DLL sideload.
- **Sysmon EID 1 (ProcessCreate)** / `DeviceProcessEvents` — `PerfWatson2.exe` from `AppData`; `choice.exe`+`del` self-delete; `schtasks` creating `GoogleUpdaterTaskSystem*`; renamed `vmtools.exe`/`vmwared.exe`/`XDRAgent.exe`.
- **Sysmon EID 3 (NetworkConnect)** / `DeviceNetworkEvents` — low-jitter HTTP beacon; contact with staging/C2 nodes.
- **IIS / web-app logs** — ASPX web-shell behavior and anomalous worker-process children.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/tinyrct_appdomainmanager_injection.yml | image_load: `*AppDomainManager.dll` from user-writable path, minus Program Files/VS |
| Sigma | sigma/tinyrct_perfwatson_masquerade_localappdata.yml | process_creation: `PerfWatson2.exe` running from AppData |
| Sigma | sigma/tinyrct_choice_selfdelete.yml | process_creation: choice.exe timer chained with `del *.exe` |
| KQL | kql/tinyrct_appdomainmanager_dll_load.kql | DeviceImageLoadEvents AppDomainManager sideload |
| KQL | kql/tinyrct_perfwatson_appdata_exec.kql | DeviceProcessEvents PerfWatson2.exe from AppData |
| KQL | kql/tinyrct_choice_selfdelete.kql | DeviceProcessEvents choice.exe delayed self-delete |
| KQL | kql/tinyrct_persistence_and_c2.kql | schtasks GoogleUpdaterTaskSystem + beacon to staging/C2 |
| YARA | yara/tinyrct_cl_sta_1062.yar | TinyRCT backdoor, loader DLL, malicious .config (3 rules) |
| Suricata | suricata/tinyrct_cl_sta_1062.rules | C2/staging IP contact + GET poll / POST exfil + payload retrieval (6 sids) |

### Threat hunting hypotheses

- **H1** — AppDomainManager sideload into a trusted launcher (`hunts/peak_h1_appdomainmanager_sideload.md`).
- **H2** — `PerfWatson2.exe` executing from the wrong location (`hunts/peak_h2_perfwatson_masquerade.md`).
- **H3** — Open-source tunnelers disguised as VMware/XDR binaries (`hunts/peak_h3_lotsource_tunneling_masquerade.md`).

## Incident response playbook

### First 60 minutes (triage)

1. Confirm the alert: identify the process loading `*AppDomainManager.dll` and/or `PerfWatson2.exe` running from `AppData`.
2. Isolate the host from the network (preserve memory if possible — TinyRCT is in-memory-active and self-deletes on command).
3. Capture the scheduled task `GoogleUpdaterTaskSystem*` (XML + action) before any cleanup.
4. Pull recent outbound connections to `45.32.113[.]172` and `139.180.134[.]221`.
5. Search for ASPX web shells on internet-facing web apps as the likely entry.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| TinyRCT binary | %LOCALAPPDATA%\PerfWatson2.exe | EDR / live response | Backdoor sample (may self-delete) |
| Loader + config | <Downloads>\chrome_setup.exe.config, MyAppDomainManager.dll | EDR / live response | AppDomainManager injection proof |
| Scheduled task | \GoogleUpdaterTaskSystem140.0.7272.0 | schtasks /query /xml | Persistence mechanism |
| Web shell | IIS web root (*.aspx) | file collection | Initial access vector |
| Web/proxy logs | IIS logs; forward proxy | SIEM | C2 beacon + web-shell requests |

### IR queries and commands

```powershell
# Find the masqueraded backdoor and its persistence
Get-ChildItem "$env:LOCALAPPDATA\PerfWatson2.exe" -ErrorAction SilentlyContinue | Select FullName,Length,CreationTime
Get-ScheduledTask | Where-Object {$_.TaskName -like 'GoogleUpdaterTaskSystem*'} | Format-List TaskName,State,Principal
schtasks /query /tn "GoogleUpdaterTaskSystem140.0.7272.0" /xml
```

```bash
# Triage captured TinyRCT POST bodies in the lab (AES-128-CBC, static key)
# key = "ThisIsASecretKey87654321" (ASCII, 24 bytes -> AES-192? validate key length in sample)
echo "Decrypt captured chunks in an isolated lab only; confirm key/IV handling from the sample."
```

```kql
DeviceNetworkEvents
| where RemoteIP in ("45.32.113.172","139.180.134.221")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc
```

### Containment, eradication, recovery

- **Containment:** isolate affected hosts; block egress to the staging/C2 nodes; disable the persistence task.
- **Eradication:** remove `PerfWatson2.exe`, the loader triplet, the scheduled task, and all ASPX web shells; rotate credentials harvested via Mimikatz (especially service accounts abused by JuicyPotato).
- **Recovery:** restore web apps from known-good builds; patch the exploited web application; re-image where source-code or credential theft is confirmed.
- **Exit criteria:** no AppDomainManager sideloads, no `PerfWatson2.exe` outside Program Files, no beacon to the C2, web shells removed and entry vector patched.
- **What NOT to do:** do not simply delete `PerfWatson2.exe` and call it done — the actor retains web-shell access and renamed tunnelers; do not skip credential rotation.

### Recovery validation

Re-run H1/H2/H3 across the estate for 14 days; verify the scheduled task does not reappear; confirm no new ASPX shells on internet-facing apps; alert on any AppDomainManager load from a user-writable path.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | 4e1f8888...425d8384 | TinyRCT backdoor (PerfWatson2.exe) | high | Unit 42 |
| sha256 | cbfe8de6...516cf7c3 | TinyRCT loader (MyAppDomainManager.dll) | high | Unit 42 |
| sha256 | 00e09754...67f0087c | chrome_setup.zip dropper | high | Unit 42 |
| sha256 | dce5df29...4fc6c87b | SoftEther VPN (renamed) | high | Unit 42 |
| sha256 | 9b481b69...cde1c472 | VNT tunneler | high | Unit 42 |
| sha256 | f34bd1d4...2071a0b1 | fscan scanner | high | Unit 42 |
| ipv4 | 45.32.113[.]172 | TinyRCT C2 (HTTP, AES-128-CBC) | high | Unit 42 |
| ipv4 | 139.180.134[.]221 | Staging / downloader | high | Unit 42 |
| string | ThisIsASecretKey87654321 | Hardcoded AES key | high | Unit 42 |
| path | %LOCALAPPDATA%\PerfWatson2.exe | Install path + guard | high | Unit 42 |
| string | GoogleUpdaterTaskSystem140.0.7272.0 | Persistence task name | high | Unit 42 |
| string | MyAppDomainManager.dll | Rogue AppDomainManager DLL | high | Unit 42 |

**CISA KEV:** this campaign has **no published CVE** (initial access is via ASPX web shells on unspecified vulnerable web applications), so there is no KEV cross-reference for this case and no `kev.md`. Absence of a CVE does not imply the entry vector is low-risk — patch internet-facing web apps and hunt for web shells regardless.

Full list (refanged) in `iocs.csv`.

## Secondary findings

- **UAT-7237 genealogy.** Unit 42 ties CL-STA-1062 to the actor Cisco Talos labeled **UAT-7237**, which in August 2025 targeted **web-hosting infrastructure in Taiwan** with a custom toolset. The evolution from opportunistic web-infrastructure attacks to targeted, long-dwell collection against SE Asian government and state-owned energy shows a maturing, regionally focused operation rather than a smash-and-grab crew.
- **Living-off-open-source as attribution cover.** The bulk of the operation rides on commodity tooling (SoftEther VPN, VNT, Yuze, Mimikatz, JuicyPotato, fscan) renamed to look like VMware/EDR binaries. This keeps development cost and attribution low; the **single bespoke component**, TinyRCT, exists only to provide low-visibility persistence with a clean exit — which is exactly why behavioral detection of TinyRCT matters more than chasing the commodity tools.
- **AppDomainManager injection as the loader primitive.** Abusing a signed .NET launcher plus a sibling `*.exe.config` to load a rogue AppDomainManager assembly (T1574.014) runs attacker code inside a trusted process at startup. It is an increasingly common, signature-resistant alternative to classic DLL search-order hijacking and deserves a standing detection independent of this actor.

## Pedagogical anchors

- **Path beats hash for masquerade.** `PerfWatson2.exe` is a real Microsoft binary name; the discriminator is that the genuine one runs from Program Files while TinyRCT runs from `%LOCALAPPDATA%`. Anchor detections on execution location, which survives recompilation.
- **A signed parent is not a safe parent.** AppDomainManager injection executes inside a legitimately signed process — code-signing trust on the launcher tells you nothing about the assembly the CLR was steered into loading.
- **Environmental guards are an analyst tell, not just evasion.** "Refuses to run outside Downloads / AppData" is both a sandbox-evasion trick and a high-fidelity behavioral signature you can hunt for.
- **No CVE is not no-risk.** Web-shell-first intrusions often lack a clean CVE to patch; the durable control is web-app hardening plus web-shell hunting, not waiting for a KEV entry.
- **Decaying vs durable IOCs.** The C2/staging IPs will rotate; the AppDomainManager sideload, the AppData-resident `PerfWatson2.exe`, and the `choice.exe` self-delete are the anchors that outlive the infrastructure.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This case write-up. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (template A, espionage accent). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | Refanged indicators (canonical schema). | [iocs.csv](./iocs.csv) |
| sigma/tinyrct_appdomainmanager_injection.yml | AppDomainManager sideload detection. | [link](./sigma/tinyrct_appdomainmanager_injection.yml) |
| sigma/tinyrct_perfwatson_masquerade_localappdata.yml | PerfWatson2.exe-from-AppData masquerade. | [link](./sigma/tinyrct_perfwatson_masquerade_localappdata.yml) |
| sigma/tinyrct_choice_selfdelete.yml | choice.exe delayed self-delete. | [link](./sigma/tinyrct_choice_selfdelete.yml) |
| kql/tinyrct_appdomainmanager_dll_load.kql | Defender XDR AppDomainManager load. | [link](./kql/tinyrct_appdomainmanager_dll_load.kql) |
| kql/tinyrct_perfwatson_appdata_exec.kql | Defender XDR PerfWatson2.exe from AppData. | [link](./kql/tinyrct_perfwatson_appdata_exec.kql) |
| kql/tinyrct_choice_selfdelete.kql | Defender XDR self-delete chain. | [link](./kql/tinyrct_choice_selfdelete.kql) |
| kql/tinyrct_persistence_and_c2.kql | Persistence task + C2/staging beacon. | [link](./kql/tinyrct_persistence_and_c2.kql) |
| yara/tinyrct_cl_sta_1062.yar | TinyRCT backdoor + loader + config (3 rules). | [link](./yara/tinyrct_cl_sta_1062.yar) |
| suricata/tinyrct_cl_sta_1062.rules | C2/staging + HTTP C2 + payload retrieval (6 sids). | [link](./suricata/tinyrct_cl_sta_1062.rules) |
| hunts/peak_h1_appdomainmanager_sideload.md | PEAK hunt H1. | [link](./hunts/peak_h1_appdomainmanager_sideload.md) |
| hunts/peak_h2_perfwatson_masquerade.md | PEAK hunt H2. | [link](./hunts/peak_h2_perfwatson_masquerade.md) |
| hunts/peak_h3_lotsource_tunneling_masquerade.md | PEAK hunt H3. | [link](./hunts/peak_h3_lotsource_tunneling_masquerade.md) |

## Sources

- [Unit 42 — CL-STA-1062 deploys TinyRCT backdoor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [The Hacker News — Chinese-Speaking APT Deploys New TinyRCT Backdoor in Southeast Asia](https://thehackernews.com/2026/06/chinese-speaking-apt-deploys-new.html)
- [Security Affairs — Chinese APT CL-STA-1062 expands attacks on SE Asian critical infrastructure](https://securityaffairs.com/194312/intelligence/chinese-apt-cl-sta-1062-expands-attacks-on-southeast-asian-critical-infrastructure-with-custom-malware.html)
- [GBHackers — Chinese-Speaking Hackers Deploy TinyRCT Backdoor (with IOC table)](https://gbhackers.com/tinyrct-backdoor-deployed/)
- [Cisco Talos — UAT-7237 targets Taiwan web infrastructure (Aug 2025)](https://securityaffairs.com/181195/apt/taiwan-web-infrastructure-targeted-by-apt-uat-7237-with-custom-toolset.html)
- [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
