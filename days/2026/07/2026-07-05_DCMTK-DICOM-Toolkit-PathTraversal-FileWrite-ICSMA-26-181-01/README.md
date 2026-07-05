---
date: 2026-07-05
title: "OFFIS DCMTK DICOM toolkit: path-traversal file write (CVE-2026-50003) + memory-exhaustion DoS across medical imaging"
clusters: ["Opportunistic medical-imaging scanners"]
cluster_country: "Global (unattributed)"
techniques_enterprise: [T1595.002, T1190, T1505.003, T1059, T1083, T1005, T1499.004]
techniques_ics: []
platforms: [linux, windows, network-edge]
sectors: [healthcare]
category: other
---

# OFFIS DCMTK DICOM toolkit: path-traversal file write (CVE-2026-50003) + memory-exhaustion DoS across medical imaging

## TL;DR
On 2026-06-30 CISA published **ICSMA-26-181-01** for five vulnerabilities in **OFFIS DCMTK** (<= 3.7.0),
the reference DICOM toolkit embedded across virtually the entire medical-imaging stack (PACS, modality
gateways, viewers, research pipelines). The headline is **CVE-2026-50003** (critical, CVSS v3.1 **9.8**):
a DICOM storage receiver builds its output filename from attacker-controlled attributes, so a
dot-segment escapes the incoming store and **writes a file to an arbitrary path** - the primitive for a
web shell or an autostart payload on the imaging host. Four more (CVE-2026-52868 path traversal;
CVE-2026-50254 / CVE-2026-35505 memory-leak DoS; CVE-2026-44628 type-confusion crash) round out
file-read, memory-exhaustion and crash impact. The bugs were reported by independent researcher
**Abhinav Agarwal** (disclosed to the vendor/CISA in May 2026) and fixed only **upstream in master** -
downstream products that vendor DCMTK cannot simply upgrade until a tagged release (>= 3.7.1) ships and
each vendor re-integrates it. There is **no confirmed in-the-wild exploitation yet**; today's entry is a
**detection-engineering build for the DICOM medical-imaging attack surface** - the first repo primary in
slot #32 (healthcare / medical device) - because DICOM has no transport authentication in most
deployments and imaging patch latency is measured in quarters.

## Attribution and confidence
This is a **vulnerability / exposure** case, not a named-actor intrusion. No cluster is attributed. The
near-term threat is **opportunistic scanning** of exposed DICOM SCPs and ransomware crews who target
hospitals for maximum operational pressure. Confidence: **low** on any single actor (none exists yet),
**high** on the technical facts (CISA advisory + a named researcher + assigned CVEs).

- **Vulnerability discovery:** independent researcher **Abhinav Agarwal**, coordinated through **CISA
  (ICSMA-26-181-01, 2026-06-30)** and OFFIS. The researcher noted he triaged the findings with LLM
  assistance and then manually confirmed them - an AI-assisted-discovery data point, not an AI attack.
- **Root cause (high confidence):** DCMTK's storage-receiving path (e.g. `storescp` / `dcmqrscp`)
  derives on-disk filenames from received DICOM attributes without fully constraining the result to the
  configured output directory (CWE-22 path traversal). The memory-leak and type-confusion flaws are
  classic C++ parser defects reached by a crafted DICOM object.

| Overlap | This case | Prior repo case |
|---|---|---|
| Open-source component embedded across many products; fix upstream, downstream lags | DCMTK vendored into PACS / viewers / gateways | 2026-07-04 FUXA SCADA/HMI (year-long unauth bug run in OSS OT software) |
| Unauthenticated pre-auth bug on an internet/VLAN-exposed service feeding mass scanning | DICOM SCP with no transport auth | 2026-07-04 FUXA (tcp/1881), 2026-06-27 Lantronix EDS (OT bridge) |
| Path-traversal file write escalating to code execution | Attribute-controlled DICOM filename -> arbitrary write | 2026-07-02 supply-chain path-write class; web-shell drops in prior AppSec cases |

Genealogy: this is the repo's **first primary in slot #32 (healthcare / medical device)**. It extends
the "OSS component, unauthenticated, exposed service" thread from FUXA (07-04) out of OT and into the
clinical imaging network, and reuses the path-traversal-to-web-shell detection pattern seen in the
AppSec cases.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| 1. Discovery / exposure | T1595.002 | Scan for DICOM SCPs; default DIMSE ports **tcp/104**, **tcp/11112**, **tcp/2762 (TLS)** |
| 2. Association | T1190 | Open an `A-ASSOCIATE-RQ` (PDU type `0x01`, app context `1.2.840.10008.3.1.1.1`) - no transport auth |
| 3. Crafted object (C-STORE) | T1190 | Send a DICOM object whose attributes drive the receiver's output filename |
| 4. Arbitrary file write | T1505.003 | Dot-segment in the derived filename escapes the store (CVE-2026-50003) into a web root / autostart |
| 5. Code execution | T1059 | Written payload is invoked; the receiver or web server spawns a shell on the imaging host |
| 6. Availability impact (alt) | T1499.004 | Crafted object triggers memory-leak/type-confusion crash (CVE-2026-50254/35505/44628) - PACS offline |

![DCMTK DICOM toolkit CVE-2026-50003 kill chain](./kill_chain.svg)

The diagram runs the **victim imaging stack** down the left lane and **attacker operations** down the
right. Detection anchors sit at two choke points: the **DICOM receiver writing a non-`.dcm` /
traversal file** (left, stage 4-5, caught by EDR file telemetry and the file-event Sigma) and the
**receiver process spawning a shell** (left, stage 5, caught by EDR) - the two events this attack
surface cannot avoid emitting. Inbound association from outside the imaging VLAN (left, stage 2) is the
early exposure signal.

## Stage-by-stage detail

### 1. Discovery and exposure
DICOM services speak DIMSE over raw TCP. Storage and Query/Retrieve SCPs listen on well-known ports and
answer an association handshake to any peer that can reach them - there is no password in a default
deployment. Exposed SCPs are trivially found by port and by the association response.

```text
# exposure fingerprint (authorized scan only)
nmap -p 104,11112,2762,2761 --open <IMAGING_CIDR>
# a C-ECHO (verification) confirms a live DICOM SCP
echoscu -aec ANY-SCP <host> 11112
```

DICOM's lack of transport authentication means **network reachability is effectively authorization**.
**MITRE:** T1595.002 Active Scanning: Vulnerability Scanning.

### 2. Association
Every DICOM conversation begins with an `A-ASSOCIATE-RQ` upper-layer PDU: first byte **`0x01`**, and the
request carries the DICOM Application Context Name **`1.2.840.10008.3.1.1.1`** plus the calling/called AE
titles. Those two constants are the network anchors for the Suricata association rules.

```text
# A-ASSOCIATE-RQ (schematic): PDU type 0x01 | reserved 0x00 | length | proto-ver |
#   called-AE(16) | calling-AE(16) | ... | Application Context "1.2.840.10008.3.1.1.1"
```

**MITRE:** T1190 Exploit Public-Facing Application.

### 3. Crafted object delivery (C-STORE)
Over an established association, a `C-STORE` operation pushes a DICOM object to the receiver. DCMTK
storage tools can construct the on-disk filename from received attributes (SOP Instance UID and, with
some options, other elements). A crafted object supplies attribute values designed to control that
filename.

```text
# a normal store (benign) - the receiver names the file from the object's UIDs
storescu -aec STORE-SCP <host> 11112 study.dcm
```

**MITRE:** T1190.

### 4. Arbitrary file write - CVE-2026-50003 (critical, CVSS 9.8)
Because the derived filename is not fully constrained to the configured output directory, a
**dot-segment** (`../`, `..\`) in the attacker-controlled component escapes the store. The receiver then
writes the received bytes to an arbitrary path - a web root served by a co-located app, a cron/systemd
or startup location, or over an existing file.

```text
# conceptual: an attribute-controlled name that resolves outside the intended store
#   <incoming_store>/../../var/www/html/shell.jsp
# Do NOT publish a working weaponized object; the control is: constrain the resolved
# path to the store and reject any '..' after normalization.
```

CVE-2026-52868 (CVSS 8.2) is the sibling path-traversal reaching the read/other paths. **MITRE:**
T1505.003 Server Software Component: Web Shell; also T1083 File and Directory Discovery / T1005 Data
from Local System for the read variant.

### 5. Code execution
Once a script/executable lands in an invocable location, execution follows: a web server serves and
runs the dropped web shell, or an autostart entry runs at the next trigger, and the DICOM host begins
spawning interpreters. The durable, vendor-independent signal is the same regardless of which write
primitive was used:

```text
# a DICOM storage receiver should NEVER spawn a shell
storescp / dcmqrscp / dcmrecv  -->  bash -c '...'   (Linux)
storescp.exe  -->  powershell.exe / cmd.exe          (Windows)
```

**MITRE:** T1059 Command and Scripting Interpreter.

### 6. Availability impact (alternative path)
Where code execution is not the goal, the same crafted-object channel denies service. CVE-2026-50254
and CVE-2026-35505 are **missing-release-of-memory** leaks; CVE-2026-44628 is a **type confusion** that
crashes the parser. A related non-DCMTK flaw, **Grassroots DICOM CVE-2026-3650**, turns a ~150-byte file
into a **4.2 GB** allocation. On a PACS this means an imaging archive taken offline or a workstation
frozen mid-read - a patient-safety event.

```text
# crash/DoS signal: WerFault on a DCMTK binary, or a receiver restart-loop,
# or a receiver RSS climbing to multi-GB on a tiny transfer (GDCM allocation bomb)
```

**MITRE:** T1499.004 Endpoint Denial of Service: Application or System Exploitation.

## Detection strategy

### Telemetry that matters
- **EDR file telemetry** on imaging hosts - Defender XDR `DeviceFileEvents`, Sysmon EID 11, Linux
  auditd file writes: a DICOM receiver writing a non-`.dcm` executable/script or a `..` path is the
  CVE-2026-50003 primitive.
- **EDR process telemetry** - `DeviceProcessEvents`, Sysmon EID 1, auditd `execve`: a DICOM receiver
  spawning `cmd`/`powershell`/`bash` is RCE; `WerFault` on a DCMTK binary is the DoS.
- **EDR / firewall network telemetry** - `DeviceNetworkEvents`, Sysmon EID 3, NetFlow: inbound to
  tcp/104, tcp/11112, tcp/2762 from outside the imaging VLAN is the exposure signal.
- **Suricata / Snort** on the imaging VLAN span - association PDU and crafted-object rules in
  `suricata/dicom_dcmtk_cve_2026.rules`.
- **SBOM / asset inventory** - which products embed DCMTK and at what version (the visibility gap that
  makes this cluster hard to close).

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma (process_creation) | `sigma/dcmtk_receiver_spawns_shell.yml` | DICOM receiver (storescp/dcmrecv/dcmqrscp/movescu) spawning a shell - post-exploit RCE |
| Sigma (file_event) | `sigma/dcmtk_receiver_file_write_traversal.yml` | DICOM receiver writing a script/exe extension or a `..` path outside the store (CVE-2026-50003) |
| Sigma (network_connection) | `sigma/dicom_inbound_association_external.yml` | Inbound association to a DICOM DIMSE port (104/11112/2762) - exposure/exploit precondition |
| KQL (Defender XDR) | `kql/dcmtk_receiver_shell_spawn.kql` | DICOM receiver -> shell child on an imaging host |
| KQL (Defender XDR) | `kql/dicom_receiver_file_write.kql` | Script/exe or `..` file written by a DICOM receiver |
| KQL (Defender XDR) | `kql/dicom_inbound_listener_external.kql` | External/non-imaging inbound to a DICOM listener |
| KQL (Defender XDR) | `kql/dcmtk_process_crash_dos.kql` | WerFault on a DCMTK binary or a receiver restart-loop (memory/type-confusion DoS) |
| YARA | `yara/dicom_dcmtk_exploit_artifacts.yar` | Crafted DICOM Part-10 objects (traversal filename / embedded exec extension) and PoC scripts |
| Suricata | `suricata/dicom_dcmtk_cve_2026.rules` | 5 rules: external association, scanner AE title, traversal/exec bytes to a storage port, DICM-over-HTTP upload |

No SPL is emitted (retired repo-wide). Convert Sigma with `sigma convert -t splunk -p sysmon <rule>.yml`.

### Threat hunting hypotheses
- **H1** - exposed DICOM listeners and associations from outside the imaging VLAN. See
  [hunts/peak_h1_exposed_dicom_listeners.md](./hunts/peak_h1_exposed_dicom_listeners.md).
- **H2** - DICOM receiver file-write escaping the store, and receiver RCE. See
  [hunts/peak_h2_dicom_filewrite_rce.md](./hunts/peak_h2_dicom_filewrite_rce.md).
- **H3** - DICOM service crash / memory-exhaustion DoS. See
  [hunts/peak_h3_dicom_service_dos.md](./hunts/peak_h3_dicom_service_dos.md).

## Incident response playbook

### First 60 minutes (triage)
1. Inventory every DICOM SCP and its exposure: `netstat`/firewall for inbound **tcp/104, 11112, 2762**;
   confirm which are reachable from outside the imaging VLAN.
2. Identify which products embed **DCMTK** and at what version (SBOM, vendor query); flag any at or
   below **3.7.0**.
3. Check EDR file telemetry (H2) for a DICOM receiver writing a non-`.dcm` executable/script or a `..`
   path; check process telemetry for a receiver -> shell child - if present, treat the host as
   compromised.
4. Check for receiver crash loops / `WerFault` on DCMTK binaries (H3) - possible active DoS.
5. Snapshot the incoming store and any co-located web root for tamper/dropped-file comparison.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| DICOM incoming store contents | receiver output dir (e.g. `/var/dicom/incoming`) | file copy | Dropped non-`.dcm` payloads, traversal writes |
| Co-located web root / autostart | web root, cron/systemd, startup | file copy | Where a traversal write lands and gets executed |
| Process execution history | EDR / Sysmon EID 1 / auditd | EDR export | Receiver -> shell = RCE |
| Receiver file writes | `DeviceFileEvents` / Sysmon EID 11 | EDR export | Files written outside the store |
| Network flow to DICOM ports | firewall / `DeviceNetworkEvents` | flow export | External reach to the SCP; source of the crafted object |
| Crashing DICOM object | quarantine copy of the last received object | file copy | Vendor analysis of the DoS trigger |

### IR queries and commands
```bash
# Linux: is a DICOM receiver shelling out or holding odd children?
for p in storescp dcmrecv dcmqrscp movescu; do pgrep -a "$p"; done
pstree -ap $(pgrep -f 'storescp|dcmqrscp|dcmrecv' | head -1) 2>/dev/null
# recent non-.dcm writes under the store / co-located web root
find /var/dicom /var/www -type f -newermt '-3 days' \
  \( -name '*.jsp' -o -name '*.php' -o -name '*.sh' -o -name '*.aspx' -o -name '*.exe' \) 2>/dev/null
```
```powershell
# Windows: DICOM receiver children and its listening sockets
Get-CimInstance Win32_Process -Filter "Name='storescp.exe' OR Name='dcmqrscp.exe'" |
  ForEach-Object { Get-CimInstance Win32_Process -Filter "ParentProcessId=$($_.ProcessId)" } |
  Select-Object ProcessId, Name, CommandLine
Get-NetTCPConnection -LocalPort 104,11112,2762 -State Listen -ErrorAction SilentlyContinue
```
```kql
// Defender XDR: DICOM receiver -> shell on any imaging host (last 14d)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("storescp.exe","storescp","dcmqrscp.exe","dcmqrscp","dcmrecv.exe","dcmrecv")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### Containment, eradication, recovery
- **Contain:** block inbound tcp/104, 11112, 2762 from non-imaging ranges at the firewall; put DICOM
  SCPs behind the imaging VLAN / a VPN; enable DICOM TLS and AE-title allowlisting where the product
  supports it. Do this before a patch exists.
- **Eradicate:** upgrade embedding products to a build that ships **DCMTK >= 3.7.1**; where a vendor
  build is not yet available, apply compensating controls (segmentation, inbound size/rate limits) and
  track the vendor's SBOM commitment. Remove any dropped payload; re-image any host where H2 fired.
- **Exit criteria:** no DICOM SCP reachable from outside the imaging VLAN; embedding products on a
  DCMTK >= 3.7.1 build (or under documented compensating controls); incoming store contains only
  `.dcm`; no receiver -> shell events; no crash loops.
- **What NOT to do:** do not assume "it only receives images, so it is low risk" - the file-write is an
  arbitrary write; do not expose a DICOM SCP to the internet under any circumstance; do not clear the
  receiver logs or the incoming store before collection.

### Recovery validation
Re-run H1/H2/H3 and confirm zero external DICOM reach, zero non-`.dcm` writes by a receiver, and zero
crash loops. Diff the incoming store and any co-located web root against a known-good snapshot. Confirm
the embedding product's DCMTK version against 3.7.1 in the SBOM.

## IOCs
Top indicators (full list in [iocs.csv](./iocs.csv), 22 entries). Valid types only. This is an
advisory-stage case: **no confirmed in-the-wild IPs/hashes/domains exist yet** - the entries below are
detection-surface and hunting anchors, not confirmed-malicious artifacts.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| cve | CVE-2026-50003 | DCMTK path traversal -> arbitrary file write; CVSS 9.8; <= 3.7.0 | high | CISA ICSMA-26-181-01 |
| cve | CVE-2026-52868 | DCMTK path traversal (sibling); CVSS 8.2; <= 3.7.0 | high | CISA ICSMA-26-181-01 |
| cve | CVE-2026-50254 | DCMTK memory-leak DoS; CVSS 7.5; <= 3.7.0 | high | CISA ICSMA-26-181-01 |
| cve | CVE-2026-35505 | DCMTK memory-leak DoS; CVSS 7.5; <= 3.7.0 | high | CISA ICSMA-26-181-01 |
| cve | CVE-2026-44628 | DCMTK type-confusion crash; CVSS 7.5; <= 3.7.0 | high | CISA ICSMA-26-181-01 |
| cve | CVE-2026-3650 | Grassroots DICOM memory-exhaustion DoS (~150 B -> 4.2 GB); 3.2.2 | medium | CISA ICSMA / SentinelOne |
| string | DICM | DICOM Part-10 magic at offset 128; crafted-object anchor | high | DICOM PS3.10 |
| string | 1.2.840.10008.3.1.1.1 | DICOM Application Context Name in every A-ASSOCIATE-RQ | high | DICOM PS3.7 |
| string | tcp/11112 | Common DICOM storescp/dcmqrscp listener | high | IANA / DICOM PS3.8 |
| path | storescp | DCMTK Storage SCP that builds filenames from attributes | high | DCMTK docs |

**CISA KEV status:** 0 of 6 CVEs are on the CISA KEV catalog at publication. The DCMTK cluster
(ICSMA-26-181-01) was published 2026-06-30 and GDCM CVE-2026-3650 earlier in 2026; none are cataloged as
exploited-in-the-wild yet. Absence from KEV is not evidence of safety - CVE-2026-50003 is a critical
unauthenticated arbitrary-file-write, so treat it as patch-when-available and segment now. See
[kev.md](./kev.md).

## Secondary findings
- **DICOM ecosystem, not one toolkit (slot #7 supply chain).** The same 2026 disclosure wave hit
  **pydicom/pynetdicom** (ICSMA-26-176-01) and **OHIF Viewers** (ICSMA-26-176-02, clinician-token theft
  via a crafted link, <= v3.12.0, 2026-06-25). DCMTK is merely the most widely embedded. The class to
  hunt is "which imaging products vendor which DICOM library, at which version" - an SBOM problem, not a
  single-CVE problem.
- **GDCM allocation bomb with no fix (slot #32).** Grassroots DICOM **CVE-2026-3650** turns ~150 bytes
  into a 4.2 GB allocation and had **no patch and an unresponsive maintainer** at disclosure. For
  GDCM-based products the only control is compensating: segment, size/rate-limit inbound objects, and
  alert on receiver RSS growth rather than waiting for a fix.
- **Exposed DICOM servers leak PHI (slot #24 CTI/exposure).** Long-running research (e.g. Trend Micro)
  has repeatedly found thousands of internet-facing DICOM/PACS endpoints exposing studies and patient
  data with no authentication. The file-write and DoS CVEs make that pre-existing exposure far more than
  a confidentiality problem.

## Pedagogical anchors
- **"It only receives images" is a dangerous assumption.** A storage receiver that derives filenames
  from received data is a file-write primitive; constrain the resolved path to the store and reject any
  `..` after normalization, exactly as you would for a web upload handler.
- **No transport auth means reachability is authorization.** DICOM in most deployments has no password;
  segmentation, AE-title allowlisting and DICOM TLS are the real access controls. Never expose a DICOM
  SCP beyond the imaging VLAN.
- **You cannot patch what you cannot see.** DCMTK is vendored into countless products with no SBOM. A
  fix "in master" does not reach a hospital until each vendor re-integrates and ships - ask vendors
  which DICOM library and version they embed.
- **Availability is a patient-safety control in healthcare.** A memory-exhaustion DoS that takes a PACS
  offline or freezes a workstation mid-read is not a nuisance outage; treat imaging availability as
  clinical safety.
- **Detect the behaviour, not just the CVE.** A DICOM receiver writing a non-`.dcm` file, spawning a
  shell, or crash-looping is the durable signal - it catches CVE-2026-50003, the sibling toolkits, and
  the next DICOM parser bug.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This write-up (15 sections). | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (victim imaging stack vs. attacker ops). | [kill_chain.svg](./kill_chain.svg) |
| sigma/dcmtk_receiver_spawns_shell.yml | Process Sigma: DICOM receiver spawning a shell (RCE). | [link](./sigma/dcmtk_receiver_spawns_shell.yml) |
| sigma/dcmtk_receiver_file_write_traversal.yml | File-event Sigma: receiver writing exec/`..` file (CVE-2026-50003). | [link](./sigma/dcmtk_receiver_file_write_traversal.yml) |
| sigma/dicom_inbound_association_external.yml | Network Sigma: inbound DICOM association to a DIMSE port. | [link](./sigma/dicom_inbound_association_external.yml) |
| kql/dcmtk_receiver_shell_spawn.kql | Defender KQL: DICOM receiver -> shell child. | [link](./kql/dcmtk_receiver_shell_spawn.kql) |
| kql/dicom_receiver_file_write.kql | Defender KQL: script/exe or `..` file written by a receiver. | [link](./kql/dicom_receiver_file_write.kql) |
| kql/dicom_inbound_listener_external.kql | Defender KQL: external inbound to a DICOM listener. | [link](./kql/dicom_inbound_listener_external.kql) |
| kql/dcmtk_process_crash_dos.kql | Defender KQL: WerFault / restart-loop of a DICOM receiver (DoS). | [link](./kql/dcmtk_process_crash_dos.kql) |
| yara/dicom_dcmtk_exploit_artifacts.yar | YARA: crafted DICOM objects and PoC-script markers. | [link](./yara/dicom_dcmtk_exploit_artifacts.yar) |
| suricata/dicom_dcmtk_cve_2026.rules | Suricata 7.x: 5 rules for the DICOM association / crafted-object surface. | [link](./suricata/dicom_dcmtk_cve_2026.rules) |
| hunts/peak_h1_exposed_dicom_listeners.md | PEAK hunt: exposed DICOM listeners + external associations. | [link](./hunts/peak_h1_exposed_dicom_listeners.md) |
| hunts/peak_h2_dicom_filewrite_rce.md | PEAK hunt: receiver file-write escaping the store + RCE. | [link](./hunts/peak_h2_dicom_filewrite_rce.md) |
| hunts/peak_h3_dicom_service_dos.md | PEAK hunt: DICOM service crash / memory-exhaustion DoS. | [link](./hunts/peak_h3_dicom_service_dos.md) |
| iocs.csv | Machine-readable indicators (22 entries). | [iocs.csv](./iocs.csv) |
| kev.md | CISA KEV cross-reference for this case's CVEs. | [kev.md](./kev.md) |

## Sources
- [CISA ICSMA-26-181-01 - OFFIS DCMTK](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-181-01)
- [HIPAA Journal - Quintet of bugs in the DCMTK DICOM toolkit](https://www.hipaajournal.com/offis-dcmtk-vulnerabilities-june-2026/)
- [NVD - CVE-2026-50003](https://nvd.nist.gov/vuln/detail/CVE-2026-50003)
- [CISA ICSMA-26-176-02 - OHIF Viewers DICOM](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-176-02)
- [CISA ICSMA-26-176-01 - pydicom / pynetdicom](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-176-01)
- [SentinelOne - CVE-2026-3650 Grassroots DICOM DoS](https://www.sentinelone.com/vulnerability-database/cve-2026-3650/)
- [GovInfoSecurity - CISA flags critical flaw in Grassroots DICOM imaging library](https://www.govinfosecurity.com/cisa-flags-critical-flaw-in-grassroots-dicom-imaging-library-a-31246)
- [Trend Micro - Exposed DICOM servers and the risk to patient data](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/a-hidden-vulnerability-in-healthcare-exposed-dicom-servers-and-the-risk-to-patient-data)
- [DCMTK - OFFIS project homepage](https://dicom.offis.de/dcmtk)
