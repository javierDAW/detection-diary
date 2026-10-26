---
date: 2026-10-26
title: "AdFection: Discover-Tech's Controlium ad platform turned targeted advertising into a zero-click delivery pipeline for Candiru mercenary spyware"
clusters: ["Candiru (Integrity Labs)", "Discover-Tech"]
cluster_country: "Israel"
techniques_enterprise: [T1189, T1203, T1583.008, T1592, T1546.015, T1027, T1071.001]
techniques_ics: []
platforms: [windows, cloud-multi]
sectors: [media, government, defense]
category: espionage
---

# AdFection: Discover-Tech's Controlium ad platform turned targeted advertising into a zero-click delivery pipeline for Candiru mercenary spyware

## TL;DR

On 2026-10-15 Citizen Lab published AdFection, an investigation of Discover-Tech, an Israeli ad-tech company whose Controlium platform lets mercenary spyware customers push malicious content to chosen people through ordinary real-time ad bidding, so a target is exposed the moment an ad renders, with no click and no message. The team links the platform to Candiru (Integrity Labs) and Bindecy, and ties at least 45 Al Jazeera Windows devices, infected in 2024 and 2025, to Candiru with high confidence. Exposed bid data shows Discover-Tech ads in 75,373 apps and 120,768 websites between March and June 2026, and Confiant reports impressions on government, defence and international-body networks. Google, IAB Europe and Beeswax removed Discover-Tech from their registries in early October. The lesson for today is that the advertising supply chain is an access channel: exposure to an ad is exposure to the attacker, and defenders must treat ad-tech domains as part of the attack surface for at-risk users.

## Attribution and confidence

| Field | Value |
|---|---|
| Cluster | Candiru (Integrity Labs), with Discover-Tech as the delivery platform operator; Bindecy and Intelos are other Controlium customers |
| Vendors and dates | Citizen Lab, 2026-10-15, co-timed with a Confiant investigation; covered by TechCrunch, The Register and CyberScoop the same day |
| Motivation | Commercial surveillance sold to governments; Citizen Lab does not identify which governments used the pipeline |
| Confidence | **High** that the Al Jazeera infections were Candiru (sample similarity with the 2021 Candiru chain plus infrastructure matches). **Medium** for Discover-Tech as the delivery platform for Candiru links (OpSec decoder page and Candiru-linked Controlium logins). **Medium to low** for the Bindecy and Intelos roles, which rest on infrastructure and logins. **Low** for any customer-government attribution, which Citizen Lab does not make |

| Overlap | Relation |
|---|---|
| Candiru 2021 Windows chain | The 2024-2025 DLL shares design with the 2021 sample (COM-hijack persistence, XOR-obfuscated strings) but uses a different persistence DLL and a different 48-byte XOR key |
| Bindecy | Mercenary hacking firm with Controlium logins from Bindecy-linked IPs and shared certificate, fingerprint and cloud-host infrastructure |
| Intelos | Mercenary ad-intelligence firm linked by `globaldatapoints.com`, an AD/HOC app, Controlium logins and a Discover-Tech shareholder |
| DARK CARTOGRAPHER | Separate cluster using Discover-Tech infrastructure since 2019; Citizen Lab announces a separate report, so nothing is claimed here |

Genealogy with earlier repo cases: this is the repo's first Candiru case. It sits next to the ProSpy / BITTER hack-for-hire case (2026-06-22) and the ToddyCat case (2026-07-06) in the mercenary-actor slot, but the delivery primitive differs: those relied on lures or implants delivered to known targets, while AdFection removes the lure and rides the ad exchange.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| 1. Ad slot won | T1189, T1583.008 | Discover-Tech bids through MyDSP, Beeswax or Eskimi; ads render in apps and sites, including in the background |
| 2. NOAS call | T1189 | The ad's script tag calls a getAd server with the advertising or cookie ID |
| 3. Eligibility check | T1592 | The server compares IP and identifiers with the tasking; non-targets get a 0-byte reply |
| 4. Tasked content | T1189, T1203 | Eligible visitors get JavaScript or a 1x1 iframe pointing to a profiling URL |
| 5. Validator probe | T1592, T1203 | A Candiru validator server checks the device before any implant is sent |
| 6. Infection | T1546.015, T1027 | Windows DLL persists by COM hijack and obfuscates strings with a 48-byte XOR key |
| 7. C2 | T1071.001 | The implant contacts `fearevolve.com` and `jobmarcher.com` after a connectivity check |

![AdFection kill chain](./kill_chain.svg)

The left lane follows one victim device from ad impression to implant; red boxes mark the delivery, infection and C2 steps. The right lane holds attribution, the Controlium platform, the exposed data, indicator limits and the detection anchors that map to the rules in this folder.

## Stage-by-stage detail

### 1. Ad slot won

Discover-Tech buys impressions through demand-side platforms and exchanges. From the March to June 2026 MyDSP bid data Citizen Lab counts 3,770,286,576 bids and 441,954,291 wins (11.7 percent), about 109,091 USD of spend, 76.7 percent in mobile apps and 23.3 percent on the web. Exchange share was Yandex 67.4 percent, Google Ad Manager 24.74 percent and Vungle 7.24 percent. Ads carrying an attacker script tag appeared in 75,373 apps and 120,768 websites.

MITRE: T1583.008 Acquire Infrastructure: Malvertising; T1189 Drive-by Compromise.

### 2. NOAS call

When the ad renders, an embedded `script` tag contacts a NOAS (getAd) server and sends the cookie ID or mobile advertising ID and cookies. Hosts named in the report:

```text
noas.mtrtb.com/getAd
noas.powerium.net/getAd
events.myweb3id.io/cplatform/getAd
infinoas.mtrtb.com
pqv2.mtrtb.com/getAd?idfa=test2
```

At least 718,748,885 bids (about 19 percent) carried NOAS script ads, across 161 countries by IP geolocation; the top countries were Yemen, Pakistan, Montenegro, Brazil, Mexico, China, Belarus, Armenia, Czechia and Israel. That is the reach of the channel, not a victim count.

MITRE: T1189.

### 3. Eligibility check

The NOAS server decides eligibility from IP and identifiers. A non-target gets a 0-byte reply, so scanners and researchers see nothing. A target gets JavaScript, usually once until re-tasked. Discover-Tech keeps the malicious code away from ad vendors, and its ad-URL OpSec encrypts parameters (AES) so the attacker can check that the visitor IP matches the impression IP, which blocks researchers from replaying links. A later "V3 OpSec" uses a custom parameter name such as `impid` and a per-user key.

MITRE: T1592 Gather Victim Host Information.

### 4. Tasked content

In the Controlium panel an operator picks a URL type (Ad URL, Test URL, Script, User Agent, Monitor, Pixel, De-anon). An "Ad URL" task returns a 1x1 iframe to the chosen URL; a "Script" task may allow arbitrary JavaScript. Targets are chosen by mobile ad ID, browser ID (MyDSP or Beeswax cookie ID) or IP. The report does not name a browser exploit or CVE.

MITRE: T1189, T1203 Exploitation for Client Execution.

### 5. Validator probe

In the Al Jazeera logs the signature is ordered: contact with Discover-Tech domains, contact with a Candiru validator server, profiling and infection, then contact with a Candiru C2 server. Validators match a published HTTP response pattern (fingerprint V1); examples are `keyadapter.com` and `sharethere.net`, with 303 more domains and 319 IPs in the report appendix.

```text
V1 (validator): HTTP/1.1 ... date, optional connection, content-type, server: Apache, content-length
C1 (C2):        HTTP/1.1 <code><space> ... Content-Type: text/html, Connection: keep-alive, server: nginx
```

MITRE: T1592, T1203.

### 6. Infection

Al Jazeera isolated a Windows DLL (SHA256 `255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8`). It persists through a COM hijack, uses a different persistence DLL than the 2021 Candiru chain, and hides strings with a 48-byte repeating XOR key and a dummy null terminator. Citizen Lab reports at least 45 affected Al Jazeera devices in 2024 and 2025.

MITRE: T1546.015 Component Object Model Hijacking; T1027 Obfuscated Files or Information.

### 7. C2

The implant checks connectivity against `http://www.google.com` and `http://www.microsoft.com` and then talks to hardcoded C2 `fearevolve.com` and `jobmarcher.com`. Two sibling C2 domains, `insightenterprisells.com` and `plasticbells.com`, match the same server fingerprint.

MITRE: T1071.001 Web Protocols.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| Candiru Windows DLL | `255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8` | Not stated in the material read | Not stated | COM-hijack persistence; strings XOR-obfuscated with a 48-byte repeating key and a dummy null terminator; connectivity check to google.com and microsoft.com; hardcoded C2 `fearevolve.com`, `jobmarcher.com` |

Because strings are XOR-obfuscated, plaintext C2 domains will not appear in the file on disk; the YARA rule therefore targets decrypted memory. The mobile exploit side of the pipeline, if any, is not described in the sources read.

## Detection strategy

### Telemetry that matters

- DNS, proxy and EDR network logs with the longest retention you have: the implant indicators are 2024-2025.
- Sysmon EID 22 (DNS query), EID 12 and 13 (registry), EID 7 (image load with hashes).
- Defender XDR: `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`.
- Network: DNS, TLS SNI for C2 and validator domains; Controlium hosts as an exposure signal.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [sigma/01_adfection_candiru_c2_dns.yml](./sigma/01_adfection_candiru_c2_dns.yml) | DNS query for the four Candiru C2 domains |
| Sigma | [sigma/02_adfection_candiru_validator_and_bindecy_dns.yml](./sigma/02_adfection_candiru_validator_and_bindecy_dns.yml) | Validator, 2025-registered and Bindecy-linked domains |
| Sigma | [sigma/03_adfection_controlium_discover_tech_infrastructure_dns.yml](./sigma/03_adfection_controlium_discover_tech_infrastructure_dns.yml) | Controlium and Discover-Tech ad-tasking hosts (exposure signal) |
| Sigma | [sigma/04_adfection_candiru_sample_dll_loaded_by_sha256.yml](./sigma/04_adfection_candiru_sample_dll_loaded_by_sha256.yml) | Image load of the published Candiru DLL hash |
| Sigma | [sigma/05_com_inprocserver32_hijack_to_user_writable_dll.yml](./sigma/05_com_inprocserver32_hijack_to_user_writable_dll.yml) | HKCU COM InprocServer32 pointing to a user-writable DLL |
| KQL | [kql/k1_adfection_candiru_c2_validator_and_bindecy_domains.kql](./kql/k1_adfection_candiru_c2_validator_and_bindecy_domains.kql) | Endpoint contact with C2, validator and Bindecy indicators over 730 days |
| KQL | [kql/k2_adfection_com_hijack_and_sample_hash.kql](./kql/k2_adfection_com_hijack_and_sample_hash.kql) | COM hijack registrations and the sample hash |
| KQL | [kql/k3_adfection_ad_impression_then_validator_then_c2_sequence.kql](./kql/k3_adfection_ad_impression_then_validator_then_c2_sequence.kql) | Ordered Controlium, validator and C2 sequence within an hour |
| YARA | [yara/adfection_strings.yar](./yara/adfection_strings.yar) | Decrypted-memory C2 strings and Controlium tasking script strings (no sample) |
| Suricata | [suricata/adfection_network.rules](./suricata/adfection_network.rules) | DNS and SNI for C2, validator and Controlium hosts, sids 6430001 to 6430004 |

### Threat hunting hypotheses

- **H1** - long-window DNS lookback for Candiru C2, validator and Bindecy domains: [hunts/peak_h1_candiru_c2_and_validator_dns_lookback.md](./hunts/peak_h1_candiru_c2_and_validator_dns_lookback.md).
- **H2** - per-user COM hijack persistence to a user-writable DLL: [hunts/peak_h2_com_hijack_persistence_user_writable_dll.md](./hunts/peak_h2_com_hijack_persistence_user_writable_dll.md).
- **H3** - exposure to the Controlium ad infrastructure: [hunts/peak_h3_ad_delivery_exposure_and_controlium_dns.md](./hunts/peak_h3_ad_delivery_exposure_and_controlium_dns.md).

## Incident response playbook

### First 60 minutes (triage)

1. Do not wipe or reimage a device with a C2 hit. Isolate it from the network, keep it powered, and capture memory first: the C2 strings are only visible after the implant decodes them.
2. Run H1 against the longest DNS, proxy and EDR history available to find the first and last contact with validator and C2 domains per device.
3. For each hit, pull the browser history and the application that rendered the ad for the hour before the first validator contact.
4. Run H2 on the affected device and its peers for COM hijack registrations, and compare any suspicious DLL with the SHA256 in `iocs.csv`.
5. Treat the user's accounts and tokens as exposed: rotate credentials, revoke sessions and review mailbox and cloud-storage access since the first contact.
6. If the user is a journalist or holds sensitive sources, assume source exposure and involve legal and the user directly before notifying anyone else.
7. Run H3 to find other users in the same exposure group and apply a protective DNS block to the Controlium domains.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Process memory and full RAM | Live host | WinPmem, EDR memory capture | Decoded C2 strings and implant configuration |
| Persistence DLL | Path in the HKCU InprocServer32 value | Offline copy, `Get-FileHash` | Compare with the published SHA256, extract for RE |
| COM registration | `HKCU\Software\Classes\CLSID\*\InprocServer32` | `reg export`, Registry Explorer | Persistence and write time |
| DNS and proxy history | Resolver, proxy, EDR network tables | KQL, `zgrep` | Validator and C2 timeline |
| Browser history and cache | Browser profile folders | Hindsight, KAPE | The site or app that served the ad |
| Mobile device backup (if the user also carries a phone) | MDM or forensic image | Vendor mobile forensics tool | Citizen Lab covers ad delivery to apps; mobile implants are not described in the sources read |

### IR queries and commands

```powershell
# Author: Jarmi
# Read-only first look: per-user COM registrations that point outside Windows and Program Files, with the DLL signature status.
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
  $k = Join-Path $_.PSPath 'InprocServer32'
  if (Test-Path $k) { $v = (Get-ItemProperty $k).'(default)'; if ($v -and $v -notmatch '^(C:\\Windows|C:\\Program Files)') { [pscustomobject]@{Clsid=$_.PSChildName; Dll=$v; Sha256=(Get-FileHash $v -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash} } }
}
```

```kql
// Author: Jarmi
// Defender XDR: every device that touched a Candiru C2, validator or Bindecy-linked domain, first and last contact.
DeviceNetworkEvents
| where Timestamp > ago(730d)
| where RemoteUrl has_any ("fearevolve.com","jobmarcher.com","insightenterprisells.com","plasticbells.com","keyadapter.com","sharethere.net","outdooutcome.com","suggestutterly.com","sincereaccertain.com")
| summarize First=min(Timestamp), Last=max(Timestamp), Hits=count() by DeviceName, RemoteUrl
```

### Containment, eradication, recovery

Exit criteria: the implant DLL and COM registration are removed or the device is rebuilt, every credential and token the user held is rotated, the Controlium and Candiru domains are blocked at the resolver, and the user's exposure group is under a protective DNS policy.

- Do NOT clean in place and return the device to a source-holding user; rebuild from known-good media, because Candiru implants are built to survive and to hide.
- Do NOT block the C2 domains before you have captured memory and the network timeline; blocking can alert the operator and cut the evidence.
- Do NOT blocklist the advertiser domains in the report (`akedo.gg`, `remindmewhere.app`, `s.taobao.com`, `king.com`): they are creatives or decoys, not infrastructure.
- Do NOT treat a clean DNS history as proof of safety unless you know its retention window.

### Recovery validation

Confirm no DNS or TLS contact with the C2 or validator domains for 30 days, no unexpected HKCU InprocServer32 values pointing to user-writable paths, and no new Controlium lookups from the user's devices. Re-run H1 to H3 on the rebuilt device.

## IOCs

No CVE, exploit or user-agent is published in the sources read. The implant indicators are from 2024-2025 and the validator list is only partly reproduced here (2 of 305 domains); load the Citizen Lab appendix for production use. Controlium hosts are ad-tech and appear in ordinary ad traffic, so treat them as exposure signals. Full list in [iocs.csv](./iocs.csv).

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | 255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8 | Candiru Windows DLL isolated by Al Jazeera | high | Citizen Lab |
| domain | fearevolve.com | Candiru C2 (hardcoded in the DLL) | high | Citizen Lab |
| domain | jobmarcher.com | Candiru C2 (hardcoded in the DLL) | high | Citizen Lab |
| domain | insightenterprisells.com | Candiru C2 by fingerprint C1 | high | Citizen Lab |
| domain | plasticbells.com | Candiru C2 by fingerprint C1 | high | Citizen Lab |
| domain | keyadapter.com | Candiru validator (fingerprint V1) | high | Citizen Lab |
| domain | sharethere.net | Candiru validator (fingerprint V1) | high | Citizen Lab |
| domain | sincereaccertain.com | Candiru profiling URLs distributed via ads from Apr 2025 | medium | Citizen Lab |
| domain | mtrtb.com | Discover-Tech NOAS, tracker and bid-data hosts | medium | Citizen Lab |
| domain | powerium.net | Controlium NOAS and logger hosts | medium | Citizen Lab |
| domain | controlium.net | Controlium control panel | medium | Citizen Lab |
| domain | myweb3id.io | Controlium event hosts | medium | Citizen Lab |
| domain | myipinfo.io | Ad-URL OpSec decoder linking Discover-Tech to Candiru links | medium | Citizen Lab |
| domain | tracookiepixel.xyz | Tracking-pixel scripts used for profiling | medium | Citizen Lab |
| string | INTEGRITYPRESALE1 | Candiru-linked Controlium account name | medium | Citizen Lab |

No CVE is in scope, so there is no `kev.md` for this case.

## Secondary findings

- **Confiant ADINT investigation (2026-10-15).** Confiant reports potentially malicious Discover-Tech ads on networks of the US Department of Defense, a Dutch ministry, Estonia's RIA, a Spanish ministry, Armenia's Prime Minister's Office, several Israeli bodies, the IAEA and the International Criminal Court. An impression is not a compromise; Citizen Lab says it is unclear whether any led to one. Read through the Citizen Lab text, not the Confiant post itself.
- **APT28 breach of a NATO naval shipbuilder (The Hacker News and The Record, about 2026-10-20/21).** Headlines report a two-month espionage campaign with a new reflective loader and Microsoft Edge abuse. Read at headline level only, so no detail is used here; a candidate for a later Monday espionage case.
- **ESET APT Activity report with China-aligned groups (2026-10).** ESET's newsroom summary mentions China-aligned groups spying in Venezuela and the Gulf and targeting AI robotics in South Korea. Summary only; not republished.

## Pedagogical anchors

- The ad exchange is a delivery channel: a mercenary customer needs only a bid, so an unclicked ad can be the first stage of a compromise.
- Targeted delivery defeats scanning: a 0-byte reply for non-targets means a researcher or a sandbox sees nothing, and the evidence sits in the victim's DNS and proxy history.
- Old indicators still matter for retro-hunting: the Candiru domains date from 2024-2025, so log retention decides whether you can answer the question.
- Combine weak signals into a sequence: ad-tech domain, then validator, then C2 within an hour is stronger than any single ad-tech hit.
- Exposure management for at-risk people (ad blocking, protective DNS) is a control, not a convenience; Citizen Lab recommends blocking ads or disabling ad tracking for anyone who may be targeted.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram (Template A). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | 59 rows: Candiru implant hash, C2 and validator domains, Controlium and Bindecy infrastructure, fingerprints and notes. | [iocs.csv](./iocs.csv) |
| sigma/ | Five Sigma rules for C2, validator, Controlium DNS, the sample hash and COM hijack. | [sigma/](./sigma/) |
| kql/ | Three KQL queries for domains, COM hijack plus hash, and the ad-validator-C2 sequence. | [kql/](./kql/) |
| yara/adfection_strings.yar | Two YARA rules for decrypted implant memory and Controlium tasking scripts (no sample). | [yara/adfection_strings.yar](./yara/adfection_strings.yar) |
| suricata/adfection_network.rules | Four Suricata rules, sids 6430001 to 6430004. | [suricata/adfection_network.rules](./suricata/adfection_network.rules) |
| hunts/ | Three PEAK hunts (H1 to H3). | [hunts/](./hunts/) |

## Sources

- [Exposing AdFection: How Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary Spyware - The Citizen Lab, 2026-10-15](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
- [Governments are hacking people with zero-click spyware by showing them online ads - TechCrunch, 2026-10-15](https://techcrunch.com/2026/10/15/citizen-lab-says-governments-are-abusing-online-ads-to-hack-people-with-zero-click-spyware/)
- [AdFection: How mercenary spyware invades victims' devices through targeted advertising - CyberScoop](https://cyberscoop.com/adfection-zero-click-spyware-discover-tech/)
- [Spyware vendors found a way to make targeted ads even worse - The Register, 2026-10-15](https://www.theregister.com/security/2026/10/15/spyware-vendors-found-a-way-to-make-targeted-ads-even-worse/5303334)
- [Russian APT28 Breaches NATO Naval Shipbuilder in NATO Country, Deploys New Reflective Loader - The Hacker News, 2026-10](https://thehackernews.com/2026/10/russian-apt28-breaches-nato-naval.html)
- [ESET Research APT Report: China-aligned groups spy in Venezuela and the Gulf, target AI robotics in S. Korea - ESET](https://www.eset.com/us/about/newsroom/research/eset-research-apt-report-2026/)
- [MITRE ATT&CK T1546.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015/)

_Source note: the Citizen Lab report was read through an automated summary of its first 100,000 characters (recommendations and correspondence sections were not read), and the other pages through search results or summaries; verify indicators and dates against the originals before blocking._
