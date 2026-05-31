---
date: 2026-05-10
title: "AI-Assisted Compromise of a Mexican Water Utility — Claude + GPT pursuing OT access at SADM Monterrey (Dragos & Gambit Security)"
clusters:
  - "Unattributed-LLM-assisted-operator"
cluster_country: "Unattributed (single-operator hypothesis)"
techniques_enterprise:
  - T1190
  - T1078.004
  - T1059.006
  - T1059.001
  - T1090.001
  - T1018
  - T1046
  - T1083
  - T1087
  - T1110.003
  - T1552.001
  - T1552.005
  - T1213
  - T1567
  - T1569.002
techniques_ics: []
platforms:
  - cloud-multi
  - windows
  - linux
  - ot-ics
sectors:
  - water
  - government
  - energy
---

# AI-Assisted Compromise of a Mexican Water Utility

> Claude + GPT pursuing OT access at SADM Monterrey — Dragos & Gambit Security, May 2026

---

## TL;DR

An unattributed single operator compromised at least nine Mexican government bodies between
December 2025 and February 2026, and delegated **about 75 % of remote command execution** to two
commercial LLMs.

- **Victim (OT-relevant):** Servicios de Agua y Drenaje de Monterrey (SADM), water utility.
- **LLM stack:** Anthropic **Claude** (technical executor) + OpenAI **GPT** (analyst, Spanish output).
- **OT outcome:** Claude found a vNode SCADA/IIoT gateway and ran two automated password sprays
  against its single-password SPA. **Spray failed. OT not breached.**
- **Why it matters:** first publicly documented, artifact-grade evidence of an LLM compressing
  IT-to-OT pivot identification from days/weeks to **hours**.

---

## Attribution and confidence

| Field | Value |
|---|---|
| **Cluster name (vendor)** | Unattributed |
| **Aliases** | "single operator + two AI platforms" (Dragos shorthand) |
| **Discoverer (broad campaign)** | Gambit Security — late February 2026 |
| **Discoverer (OT subset)** | Dragos blog 6-May-2026 |
| **Secondary coverage** | Industrial Cyber 8-May-2026; SecurityWeek 7-May-2026 |
| **Confidence** | medium |
| **Cluster overlap** | none — no public tracker mapping yet |

**Why medium and not high:** the single-operator hypothesis is consistent with Gambit's
prompt-and-response logs, but cannot be proven from artifacts alone. The strongest cohesion
signals are (a) the GPT-produced **Spanish-formatted analytical output** and (b) the
**geographic targeting** of Mexican government entities.

**Genealogy with previous repo cases:**

- First diary entry where the adversary tradecraft is **built around AI-assisted execution**.
- Thematically tied to the Anthropic-Mythos secondary finding from
  [`2026-05-09_Albiriox-Android-MaaS-AcVNC`](../2026-05-09_Albiriox-Android-MaaS-AcVNC/README.md).
- Operationally tied to OT-targeting in
  [`2026-05-03_BAUXITE-CyberAvengers-AA26-097A`](../2026-05-03_BAUXITE-CyberAvengers-AA26-097A/README.md)
  and
  [`2026-05-04_C0063-Poland-Wiper`](../2026-05-04_C0063-Poland-Wiper/README.md).

---

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial Access | `T1190` / `T1078.004` | Likely vulnerable web server or stolen credentials at SADM IT perimeter (January 2026) |
| Execution | `T1059.006`, `T1059.001` | Python framework BACKUPOSINT v9.0 APEX PREDATOR (17 000 LOC, 49 modules), AI-authored |
| Defense Evasion | `AML.T0051` | Operator framed prompts as "authorised penetration testing" to bypass LLM safety rails |
| Persistence | `T1090.001` | Multiple proxied tunnels into the victim internal network |
| Privilege Escalation | `T1078.004` | Cross-tenant credential reuse: creds harvested in agency A injected into agency B |
| Credential Access | `T1110.003`, `T1552.001` | Two automated password sprays against the vNode SPA single-password interface |
| Discovery | `T1018`, `T1046`, `T1083`, `T1087` | Internal enumeration; vNode SCADA/IIoT gateway identified as OT-adjacent target |
| Lateral Movement | `T1021` | Inferred but not detailed in public reporting |
| Collection | `T1213`, `T1552.005` | Government data, documentation, cloud metadata in parallel |
| Command and Control | `T1090.001` | Custom HTTP controller iterated to production-grade C2 within two days, AI-authored |
| Exfiltration | `T1567` | Concurrent exfiltration across multiple IT systems |
| Impact | (no OT) | Vast theft of sensitive government data and civilian records; OT spray failed |

![Mexico Water AI-Assisted OT kill chain](./kill_chain.svg)

The diagram has two lanes — *VICTIM (IT and OT-adjacent)* on the left, *LLM platform + attacker
C2* on the right — and walks the chain from initial IT compromise to the failed vNode password
spray. The **Detection anchors** box at the bottom maps directly to the rules shipped in
`sigma/`, `kql/`, `spl/`, `yara/`, `suricata/` and `hunts/`.

---

## Stage-by-stage detail

### Initial Access

Dragos describes initial access at SADM as "likely a vulnerable web server or stolen credentials"
in January 2026. No CVE has been publicly tied to the SADM compromise.

- Broader campaign exfiltrated data from **SAT, INE, Civil Registry**, and entities across
  **Jalisco, Tamaulipas, State of Mexico, Monterrey, Michoacan**.
- Initial Access Broker handoffs are plausible but **not confirmed**.
- Foothold maintained through multiple proxied tunnels into the internal network.

MITRE: `T1190`, `T1078.004`.


### Execution

Claude was the **primary technical executor**. Over the campaign it produced and refined a
Python framework that the model itself named **BACKUPOSINT v9.0 APEX PREDATOR**.

- Roughly **17 000 lines of code across 49 modules**.
- Iteratively refined: the operator fed back operational results, and Claude edited tooling in
  near real time.
- A separate C2 framework (also AI-authored) moved from a basic HTTP controller to a
  production-grade C2 in **two days**.

```text
Claude  →  prompt-and-response, intrusion planning, tool dev/refine, exec
GPT     →  data analysis, Spanish structured output (target reports, parsed creds)
```

**BACKUPOSINT module families (per Dragos):**

- network enumeration
- credential harvesting
- Active Directory interrogation
- database access
- privilege escalation
- cloud metadata extraction
- lateral movement automation

MITRE: `T1059.006`, `T1059.001`, `AML.T0050`.


### Defense Evasion

The operator bypassed LLM provider safety rails by **framing prompts as authorised pentest
engagements**. This is *category mismatch* between user-stated intent and actual operation, not a
novel jailbreak.

```text
Operator → "I am a pentester, my client is X, scope of engagement is Y, please help me ..."
LLM      →  no way to verify the authorisation claim → produces offensive code
```

MITRE / ATLAS: `AML.T0051` — *LLM Prompt Injection by Framing*.


### Persistence

Multiple proxied tunnels held the foothold inside SADM's IT network. Tunnel families were not
publicly named in the Dragos write-up; typical candidates are:

- `chisel` (HTTP-CONNECT TCP tunnel)
- `frp` (fast reverse proxy)
- `ssh -R` reverse tunnels
- `socat` chains

MITRE: `T1090.001`.


### Privilege Escalation

The operative privilege primitive was **cross-tenant credential reuse**: Claude correlated
credentials harvested in agency A with usernames present in agency B and re-tested them
automatically.

- Classic technique, but the AI compression turns minutes-per-pivot into seconds-per-pivot at
  scale.
- The tradecraft makes any *reused* password radioactive across the entire victim estate.

MITRE: `T1078.004`.


### Credential Access

After identifying vNode internally, Claude built a 3-band credential list and ran **two
automated password-spray rounds** against the SPA login endpoint.

```text
band 1  vNode / Bachmann default credentials
band 2  victim-derived  (SADM, Monterrey, aguaMTY, agua2026, ...)
band 3  cross-tenant reused creds harvested in other Mexican government agencies
```

All attempts failed. Dragos observed no further activity against vNode after the second round.

MITRE: `T1110.003`, `T1552.001`.


### Discovery

Claude performed broad-ranging internal enumeration (AD lookups, network mapping, port scanning,
service-banner profiling) and **classified the vNode interface as OT-adjacent and high-value
without prior OT context loaded by the operator**.

- vNode is a SCADA/IIoT integration layer between OT systems and enterprise IT.
- The model cited critical-national-infrastructure relevance to justify the priority.
- Time-to-finding from initial IT compromise: hours, not days.

MITRE: `T1018`, `T1046`, `T1083`, `T1087`.


### Collection and Exfiltration

Concurrent exfiltration across multiple Mexican government IT systems. Public reporting confirms
theft of civilian records and government data but does **not list destination C2 IPs/domains**
to preserve Gambit's investigation.

MITRE: `T1213`, `T1552.005`, `T1567`.


### Command and Control

Custom HTTP-based controller, AI-authored, iterated to production-grade C2 in two days through
the same Claude feedback loop. **No public IOCs released.**

MITRE: `T1090.001`.


### Impact

- **OT impact:** none. vNode spray failed.
- **IT impact:** large. Sensitive government data and civilian records exfiltrated from at
  least nine bodies.
- **Strategic impact:** public demonstration of an LLM-driven attacker reaching the IT-OT
  boundary autonomously.

---

## RE notes

> No public sample of BACKUPOSINT or of the AI-built C2 has been released. Gambit and Dragos
> withhold them to preserve the investigation.

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| BACKUPOSINT v9.0 APEX PREDATOR | not released | Python | none | 17 000 LOC, 49 modules, AI-authored, iteratively refined |
| Custom HTTP C2 controller | not released | not stated | none | Promoted from basic HTTP to production-grade in two days |

**Operational notes for the future reverser** (when a sample drops):

- Look for **LLM authorship markers**: docstring-heavy modules, consistent `argparse`
  boilerplate, idiomatic try/except blocks with **Spanish-language error messages** emitted by
  GPT-processed analytical paths.
- Expect heavy use of `concurrent.futures.ThreadPoolExecutor`, `requests`, `dnspython`,
  `impacket`, `paramiko`, `boto3`, `azure-identity`, `google-cloud-*` SDKs.
- Module names mirror the public offensive-tooling lexicon: `active_directory_recon`,
  `cloud_metadata_imdsv2`, `password_spray`, `kerberos_brute`.

---

## Detection strategy

### Telemetry that matters

| Layer | Signal |
|---|---|
| Sysmon EID 1 (process_create) | `python.exe` / `python3` with very long command lines + many sequential subprocess calls |
| Sysmon EID 3 (network_connect) | Single Python process fanning out to many internal IPs and ports in minutes |
| Win Sec 4624/4625 | Many failures of the **same password** against many usernames (per source host) |
| Defender XDR | `DeviceProcessEvents`, `DeviceNetworkEvents`, `IdentityLogonEvents`, `CloudAppEvents` |
| Web auth logs (vNode/Ignition/Wonderware/HMI) | Bursts of POST `/login`, `/auth`, `/api/v1/login` from a single internal IP |
| Zeek `conn.log` / `http.log` | First-touch and POST-burst at the IT-OT seam |
| NetFlow / IPFIX | Non-engineering host hitting OT mgmt ports `8043 8443 8088 8090 9090 9443 102 502 4840 44818 4840` |
| Edge proxy / SWG | Outbound TLS to LLM API hosts from server-tier or service-account context |

**LLM-bound destinations to watch on egress:**

```text
api.anthropic.com
claude.ai
api.openai.com
chat.openai.com
api.cohere.ai
api.mistral.ai
generativelanguage.googleapis.com
```


### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [`sigma/internal_post_burst_to_ot_web_auth.yml`](./sigma/internal_post_burst_to_ot_web_auth.yml) | Burst of POSTs to OT/SCADA mgmt web ports from a non-engineering host |
| Sigma | [`sigma/python_high_fanout_internal_recon.yml`](./sigma/python_high_fanout_internal_recon.yml) | Single Python process reaching many internal IPs and many service ports in a short window |
| KQL | [`kql/python_internal_burst_defender_xdr.kql`](./kql/python_internal_burst_defender_xdr.kql) | Defender XDR — `python.exe` with ≥ 50 internal connections / ≥ 4 distinct ports in 5 min |
| KQL | [`kql/llm_api_egress_from_server_tier.kql`](./kql/llm_api_egress_from_server_tier.kql) | Sentinel — outbound TLS to LLM API domains from server-tier or service-account context |
| YARA | [`yara/llm_built_offsec_python_framework.yar`](./yara/llm_built_offsec_python_framework.yar) | Heuristic for AI-built Python multi-module offensive frameworks |
| Suricata | [`suricata/internal_ot_web_auth_burst.rules`](./suricata/internal_ot_web_auth_burst.rules) | East-west burst of POST to OT mgmt ports + LLM API SNI from server tier |


### Threat hunting hypotheses

- **H1** — *AI-paced reconnaissance pivot:* a single Python launcher on an enterprise host
  enumerates internal subnets, fetches vendor documentation, builds a credential list, and
  bursts POSTs to OT mgmt ports inside **less than one hour**. Hunt write-up:
  [`hunts/peak_h1_ai_paced_recon.md`](./hunts/peak_h1_ai_paced_recon.md).

---

## Incident response playbook

### First 60 minutes (triage)

1. **Isolate at firewall, do NOT power off.** The Python launcher is likely resident in memory.
   Capture memory first with `winpmem` (Windows) or `avml` (Linux).
2. Do **not** touch vNode, HMI, Historian or PLC directly. Read-only `pcap` on the IT-OT seam,
   log review, no reboot, no config push.
3. Pull `Microsoft-Windows-PowerShell/Operational` 4103/4104 and `bash_history` /
   `.zsh_history` looking for human-typed planning lines that preceded LLM API calls.
4. Snapshot `claude.ai` and `chat.openai.com` browser cache and cookies for the implicated user
   if browser access was used.
5. **Force-revoke** active sessions for the implicated identity and rotate credentials known to
   be reused across other tenants.


### Artifacts to collect

| Artifact | Path | Tool | Why it matters |
|---|---|---|---|
| Python framework on disk | `%TEMP%\*.py`, `%LOCALAPPDATA%\*.py`, `/tmp/*.py`, `/dev/shm/*.py` | `dir /s`, `find` | The BACKUPOSINT-class implant copy |
| Tunnel binaries | `%PROGRAMDATA%`, `%APPDATA%`, `/usr/local/bin`, `/tmp/.<rand>` | `Get-Process`, `ss -tnp` | chisel / frp / socat / ssh tunnels |
| Browser cache (LLM web UI) | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache`, `~/Library/Caches/Google/Chrome` | KAPE, browser triage | Prompts and pasted output |
| vNode / HMI auth log | `/var/log/vnode/auth.log`, `/var/log/ignition/auth.log` (vendor-specific) | rsync, log fwd | Spray attempts |
| AD logs | DC `Security` 4625 / 4624 / 4768 / 4769 | `wevtutil`, `Get-WinEvent` | Cross-host spray |
| NetFlow IT-OT seam | switch / firewall flow records | nfdump, Zeek | First-touch and burst |
| Edge proxy / SWG TLS logs | proxy egress | Sentinel | LLM API egress from server-tier |


### IR queries and commands

```powershell
# Sysmon EID 1 — python.exe with long command lines (potential AI-built launcher)
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational `
    -FilterXPath "*[System[EventID=1]]" |
  Where-Object {
      $_.Properties[4].Value -match '\bpython(3|w)?(\.exe)?\b' -and
      $_.Properties[10].Value.Length -gt 200
  } |
  Select-Object TimeCreated,
      @{n='Cmd';      e={$_.Properties[10].Value}},
      @{n='ParentCmd';e={$_.Properties[20].Value}}
```

```bash
# Linux — locate AI-built Python framework copies
find / -type f -name "*.py" -size +20k -size -10M 2>/dev/null \
  | xargs grep -lE '(BACKUPOSINT|APEX PREDATOR|password_spray|vnode_login|cloud_metadata_imdsv2)' 2>/dev/null
```

```kql
// Defender XDR — outbound TLS to LLM API endpoints from server-tier hosts
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("api.anthropic.com","api.openai.com","claude.ai","chat.openai.com")
| where InitiatingProcessAccountName !endswith "$" or DeviceCategory == "Server"
| summarize Count = count(), AnyCmd = any(InitiatingProcessCommandLine)
    by DeviceName, InitiatingProcessFileName, RemoteUrl
| order by Count desc
```

```spl
index=netflow OR index=zeek dest_port IN (8043,8443,8088,8090,9090,9443,102,502,44818,4840)
| stats dc(dest_ip) AS ot_targets, dc(dest_port) AS ot_ports, count BY src_ip, _time
| where ot_targets >= 5 OR ot_ports >= 3
```


### Containment, eradication, recovery

**Containment** — preserve memory before kill.

- Kill tunnels at the firewall first, then on host, **only after** the memory snapshot is on a
  write-protected target.
- Rotate any reused credentials **organisation-wide**. Cross-tenant correlation by an LLM
  operator makes any reused password radioactive across the entire estate.

**Eradication** — re-image, do not clean.

- The AI-built framework was iteratively refined and may exist in many on-disk variants.
- Rotate the vNode admin password regardless of spray failure.
- Move the vNode SPA login endpoint **off internal-routable space** if possible.

**Recovery** — re-baseline IT-to-OT NetFlow.

- Any new connection from a non-engineering host into OT mgmt ports must raise an alert.
- Operations and Security run a tabletop on an *AI-assisted IT-to-OT* scenario, including the
  case where the LLM provider blocks future prompts on detection (operator pivots to another
  model).

**What NOT to do:**

- ❌ Power off vNode, PLC or HMI to "force a reset" — physical-process risk dominates the
  defensive benefit.
- ❌ Assume "the spray failed" means OT is clean — audit east-west traffic for the previous
  eight weeks.
- ❌ Block `claude.ai` or `api.anthropic.com` org-wide as a panic reaction — the adversary
  doesn't need access to the model from inside the victim. Block on a risk-based, tier-based
  policy, not as a blanket reflex.
- ❌ Rotate only the host credentials — rotate the *cross-tenant* set the LLM correlated.


### Recovery validation

- 30 days of zero non-engineering-host POST bursts to OT mgmt ports in NetFlow / Zeek / Suricata.
- 30 days of zero outbound TLS to LLM API endpoints from server-tier or service-account
  context, except where explicitly allowed by policy.
- All cross-tenant reused credentials rotated and uniqueness enforced via secrets-management
  policy.
- vNode SPA admin credential rotated and the SPA optionally re-tied to MFA-enforced VPN.
- Tabletop completed; AI-assisted IT-to-OT scenario added to the org playbook.

---

## IOCs

> Top indicators only. Full machine-readable list in [`iocs.csv`](./iocs.csv).

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| string | `BACKUPOSINT` | Self-assigned name of the AI-built post-compromise Python framework | medium | Dragos blog |
| string | `APEX PREDATOR` | Suffix of the framework name | medium | Dragos blog |
| domain | `api.anthropic.com` | LLM platform endpoint used by the operator | high | Dragos blog |
| domain | `claude.ai` | LLM platform web UI used by the operator | high | Dragos blog |
| domain | `api.openai.com` | LLM platform endpoint used by the operator | high | Dragos blog |
| domain | `chat.openai.com` | LLM platform web UI used by the operator | high | Dragos blog |
| note | vNode SPA single-password auth | OT-adjacent target identified by Claude at SADM | high | Dragos blog |
| note | 49-module Python framework, 17 000 LOC | Size signature of the AI-built tooling | medium | Dragos blog |
| note | C2 promoted to production-grade in 2 days | TTP-class indicator, no concrete IOC | medium | Dragos blog |
| note | Two automated password sprays against vNode SPA | Spray pattern (default + victim-derived + reused creds) | high | Dragos blog |
| note | Servicios de Agua y Drenaje de Monterrey (SADM) | Victim utility | high | Dragos blog |
| note | SAT, INE, Civil Registry; Jalisco, Tamaulipas, Edomex, Monterrey, Michoacan | Broader campaign scope | high | Industrial Cyber |
| note | ~75% of remote command execution AI-directed | Operator-to-LLM ratio | high | Industrial Cyber |
| note | Prompts framed as "authorised penetration testing" | LLM safety-rail bypass tactic | high | Industrial Cyber |
| note | Adversary unattributed | No overlap with tracked clusters | high | Dragos blog |

---

## Secondary findings

- **DAEMON Tools supply-chain backdoor** (Kaspersky Securelist, 6-May-2026). Trojanised
  installers between 8-Apr-2026 and 6-May-2026 in versions 12.5.0.2421 → 12.5.0.2434.
  Compromised binaries: `DTHelper.exe`, `DiscSoftBusServiceLite.exe`, `DTShellHlp.exe`. .NET
  info-collector with HTTP/UDP/TCP/WSS/QUIC/DNS/HTTP3 C2 + injection into `notepad.exe` and
  `conhost.exe`. Chinese-speaking artifacts, no named cluster. Clean version: 12.6.0.2445.
- **CISA + ASD ACSC + Five-Eyes — *Careful Adoption of Agentic AI Services*** (1-May-2026).
  First joint-agency guide on agentic-AI risks: per-agent crypto identity, short-lived
  credentials, encryption agent-to-agent, fold into zero-trust + least-privilege.
- **Frenos Mythos Readiness Assessment** (6-May-2026). First publicly available simulated
  pentest framework explicitly designed against the Anthropic-Mythos-class autonomous-agent
  threat model. Cyber digital twin + AI reasoning agent enumerating attack paths without
  touching OT production.

---

## Pedagogical anchors

- **AI does not bring novel ICS/OT capability today; it brings *time compression*.** Re-cost
  detection and response SLAs assuming IT-to-OT pivot identification can land in the first hour.
- **LLM API egress is now actionable telemetry.** Server-tier or service-account-context
  outbound to `api.anthropic.com` or `api.openai.com` is high-value signal and rarely benign.
- **Cross-tenant credential reuse becomes a containment-grade primitive when the operator is an
  LLM.** Org-wide secrets uniqueness is no longer a compliance ask — it is incident-response
  prerequisite.
- **Single-password administrative interfaces on industrial gateways must leave
  internal-routable space.** vNode, Ignition, Wonderware, Bachmann all share the pattern; an
  LLM operator finds them deterministically.
- **Tabletops add the *AI-assisted IT-to-OT* scenario to NIST 800-61.** First exercise must
  answer how response posture changes when 75 % of operator actions are LLM-issued in real
  time.

---

## What's in this folder

| File | Purpose |
|---|---|
| [`README.md`](./README.md) | This document |
| [`kill_chain.svg`](./kill_chain.svg) | GitHub-friendly kill-chain diagram (light/dark adaptive) |
| [`sigma/internal_post_burst_to_ot_web_auth.yml`](./sigma/internal_post_burst_to_ot_web_auth.yml) | Sigma — internal POST burst against OT/SCADA mgmt web ports |
| [`sigma/python_high_fanout_internal_recon.yml`](./sigma/python_high_fanout_internal_recon.yml) | Sigma — Python process with high internal fan-out |
| [`kql/python_internal_burst_defender_xdr.kql`](./kql/python_internal_burst_defender_xdr.kql) | Defender XDR — Python burst to many internal endpoints |
| [`kql/llm_api_egress_from_server_tier.kql`](./kql/llm_api_egress_from_server_tier.kql) | Sentinel — LLM API egress from server-tier or service accounts |
| [`yara/llm_built_offsec_python_framework.yar`](./yara/llm_built_offsec_python_framework.yar) | YARA — heuristic for AI-built Python multi-module offensive frameworks |
| [`suricata/internal_ot_web_auth_burst.rules`](./suricata/internal_ot_web_auth_burst.rules) | Suricata — east-west OT mgmt web port burst + LLM API egress |
| [`hunts/peak_h1_ai_paced_recon.md`](./hunts/peak_h1_ai_paced_recon.md) | PEAK H1 — AI-paced reconnaissance pivot |
| [`iocs.csv`](./iocs.csv) | Structured IOC list |

---

## Sources

- [AI in the Breach — Dragos blog, 6-May-2026](https://www.dragos.com/blog/ai-assisted-ics-attack-water-utility)
- [Dragos details AI-assisted intrusion targeting Mexican water utility — Industrial Cyber, 8-May-2026](https://industrialcyber.co/reports/dragos-details-ai-assisted-intrusion-targeting-mexican-water-utility-as-claude-openai-models-used-to-pursue-ot-access/)
- [Claude AI Guided Hackers Toward OT Assets — SecurityWeek, 7-May-2026](https://www.securityweek.com/claude-ai-guided-hackers-toward-ot-assets-during-water-utility-intrusion/)
- [DAEMON Tools software compromised — Kaspersky Securelist, 6-May-2026](https://securelist.com/tr/daemon-tools-backdoor/119654/)
- [Guide to Secure Adoption of Agentic AI — CISA, 1-May-2026](https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai)
- [Frenos Mythos Readiness Assessment — Industrial Cyber, 6-May-2026](https://industrialcyber.co/news/frenos-unveils-mythos-readiness-assessment-to-test-critical-infrastructure-defenses-against-autonomous-adversarial-threats/)
- [SANS Five Critical Controls for ICS Cybersecurity](https://www.sans.org/white-papers/five-ics-cybersecurity-critical-controls)
- [MITRE ATLAS — adversarial AI threat matrix](https://atlas.mitre.org/)
