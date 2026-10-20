---
date: 2026-10-20
title: "Silent Ransom Group leaked chats: 3CX callback funnel, IT-impersonation vishing, in-person agents and the Sleepless Threat spin-off"
clusters: ["Silent Ransom Group (SRG)", "Luna Moth", "Chatty Spider", "UNC3753", "Sleepless Threat"]
cluster_country: "Russia-linked (per The Record); operators not identified"
techniques_enterprise: [T1589.002, T1591.004, T1593.001, T1583.001, T1585.003, T1650, T1566.004, T1684.001, T1219, T1200, T1091, T1199, T1005, T1052.001, T1567.002, T1657]
techniques_ics: []
platforms: [windows]
sectors: [legal, finance, insurance, healthcare, defense]
category: ransomware
---

# Silent Ransom Group leaked chats: 3CX callback funnel, IT-impersonation vishing, in-person agents and the Sleepless Threat spin-off

## TL;DR

An archive of 5,692 internal chat messages attributed to Silent Ransom Group (SRG, also Luna Moth, Chatty Spider, UNC3753) surfaced on a .onion site in early October 2026, and three outlets analysed it within nine days: The Record (2026-10-08), KELA (2026-10-13) and GuidePoint GRIT (2026-10-15). The chats cover 2025-08-27 to 2026-09-29 and describe an extortion-only crew that uses a phone call and a legitimate remote-access tool instead of malware, with a second model in which US-based "agents" visit offices in person. The group's own ledger claims about USD 206.95M from 27 of 50 organisations, mostly large US law firms, which no outsider has verified; wallets named in the chats received about 37 BTC (about USD 3M) on-chain. The case matters today because the leak shows the whole workflow, including the infrastructure list and the defensive gaps it exploits, and because the only host artefact on a victim endpoint is a tool your help desk may also use.

## Attribution and confidence

| Field | Value |
|---|---|
| Cluster | Silent Ransom Group (SRG) and a spin-off brand, Sleepless Threat (new name from September 2026) |
| Aliases | Luna Moth (KELA, GuidePoint), Chatty Spider (The Record), UNC3753 (Mandiant) |
| Active since | At least 2022 (FBI, via KELA); law-firm targeting since spring 2023 |
| Vendors and dates | The Record 2026-10-08; KELA 2026-10-13; GuidePoint GRIT 2026-10-15 (chat export received 2026-10-06) |
| Motivation | Financial: data theft and extortion, no encryption |
| Confidence | **medium**. KELA states that the archive's authenticity is unverified. GuidePoint assesses moderate-to-high confidence that the chat personas operate under or alongside the SRG name. Chainalysis tied addresses in the leak to known SRG extortions (The Record), and says it cannot speak to the totality of the claims. |

| Overlap | Relation |
|---|---|
| Repo case 2026-06-24 (SRG / Luna Moth fast flux) | Same actor. That case covers DNS fast flux infrastructure and RMM-based vishing from vendor reporting; this one covers the leaked operational workflow: roles, access models, in-person agents, ledger and the Sleepless spin-off. No indicator or rule is repeated. |
| Repo case 2026-07-28 (Akhter insider, federal database deletion) | Different mechanism. Here the insider path is planned and recruited from outside (contractor pretext, agents); there is no employee insider in the sources. |
| Repo case 2026-06-23 (Cloud insider recruitment) | Related theme, recruiting people with access; different actor and medium. |

Anti-duplicate check: `grep -rliE 'sleepless|slplsskdj|aim6umein|3cx'` over `days/`, `byActor/` and `INDEX.md` before publishing found only the 2026-06-24 SRG case as the same actor.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Target selection | T1589.002, T1591.004, T1593.001 | Roster of 20 firms posted 2026-07-30 to 2026-09-04: managing partners, COOs, CIOs, general counsel, and in 13 cases the firm's cyber or privacy partner; LinkedIn research; endpoint counts and security products noted per firm |
| Pretext infrastructure | T1583.001, T1585.003 | Lookalike IT and law-firm domains (-it.com, it-.com, -law.com patterns), Google Voice numbers and Gmail accounts per firm, a 3CX PBX on a rented Netherlands VPS |
| Contact | T1566.004 | MAIN model: bulk email with a PDF that shows a support number, victim calls in. TRG/SPR model: a scheduled call to a named executive, then a hand-off from "IT" to a "specialist" |
| Remote session | T1219, T1684.001 | Victim is talked into a session with AnyDesk, Zoho Assist or Quick Assist (GuidePoint) or Zoom, Teams and Quick Assist (KELA) |
| Physical fallback | T1200, T1091, T1199 | An agent visits the office posing as IT and uses a remote tool on the target's machine; a USB drive is discussed for delivering the tool; contractor and cleaner pretexts are planned |
| Collection and exfiltration | T1005, T1567.002, T1052.001 | Files to Google Drive accounts (100 GB) and rented SSH servers (600 GB each); one law firm letter confirms files copied to a flash drive |
| Extortion | T1657 | Labels CHAT, OFFER, CONTRACT, GOLD; median 5.5x from first offer to payment over 22 cases in a median of 10 days (GuidePoint) |

![SRG leaked chats kill chain](./kill_chain.svg)

The left lane follows the victim organisation from target research to the extortion call; red stages (3 to 6) are the ones a defender can still interrupt with a verification step, a tool allow-list or a physical control. The right lane holds the operator side: roles, infrastructure, agent recruiting, the money claims and the source conflicts. Detection anchors are the first-seen remote tool, the USB mount, the lookalike sender domain and the published infrastructure.

## Stage-by-stage detail

### Stage 1: target selection and research

GuidePoint reports a roster of 20 firms between 2026-07-30 and 2026-09-04. Selection favoured larger firms because they offer more entry points; the chats record the number of endpoints and the installed security products per firm. Targets were named people, including, in 13 cases, the firm's own cyber or privacy partner. Techniques: T1589.002 and T1589.003 (identity information), T1591.004 (roles), T1593.001 (social media).

### Stage 2: pretext infrastructure

The group rented or registered domains that imitate IT providers or law firms, issued mailboxes on them, and bought disposable Google Voice numbers and Gmail accounts per firm. Domains named in the chats for August to September 2025 are `sokolovsky-law[.]com`, `ominetdata[.]com`, `develevenor[.]com` and `funconnect[.]com`. The telephony for the MAIN model ran on a 3CX PBX hosted on a rented VPS in the Netherlands. Staging used Google Drive accounts and rented SSH servers; the chat itself ran on self-hosted Rocket.Chat, with Telegram and SimpleX for contact with victims. Techniques: T1583.001, T1585.003, T1650.

```text
Rocket.Chat (main)       aim6umein3kee[.]com
Rocket.Chat (Sleepless)  slplsskdj2836v2jjsx[.]com   (from 2026-09-02)
RDP "SLEEPLESS RDP WORK" 45[.]32[.]232[.]133:2895
SSH staging (600 GB)     199[.]217[.]98[.]21, 216[.]203[.]20[.]157
```

### Stage 3: first contact, two access models

MAIN, the callback funnel, used bulk phishing emails with a PDF that carries a support number. The victim calls the number and reaches operators who pose as IT support. GuidePoint reports this model as degraded by June 2026. TRG/SPR, the targeted model, ran to the end of the data: a scheduled call to a named executive, a caller who claims to be the firm's IT department and then passes the person to a named "specialist". Technique: T1566.004 (voice phishing).

### Stage 4: the remote session

The operator walks the victim into a remote-access session and takes control. GuidePoint names AnyDesk, Zoho and Quick Assist in the chats and cites the FBI notice for Syncro, Atera and Splashtop; KELA names Zoom, Teams and Quick Assist. No CVE, exploit, encryptor or custom malware is reported; a USB stealer was proposed, rejected and raised again the next day. Techniques: T1219, T1684.001 (impersonation, as listed by GuidePoint).

```text
Host artefacts to check: process start of the remote tool, its service or installer, session traces
AnyDesk: %ProgramData%\AnyDesk\ad_svc.trace, %APPDATA%\AnyDesk\ad.trace
Quick Assist: process quickassist.exe; DNS remoteassistance.support.services.microsoft.com
```

### Stage 5: the physical fallback

When the remote route fails, an agent can arrive in person. GuidePoint describes a call that books a visit, an agent on site who uses remote-access software on the target's machine, and a USB drive discussed for delivering the tool. Pretexts discussed include deliveries, cloned access cards and a cleaning-contractor insider; some of these are plans only. The FBI warned earlier that members posed as IT staff to reach computers, and a New York law firm's letter, quoted by The Record, describes files copied to a flash drive in its office. Roughly 10 to 15 US-resident helpers appear; recruiting used Telegram ads disguised as ordinary jobs, at about USD 200 per advert, with about USD 1,300 per forged ID; the leader estimated that one recruit in ten was usable. Techniques: T1200, T1091, T1199 (planned), T1052.001.

### Stage 6: collection and exfiltration

Files are collected from the target machine and moved to attacker-controlled storage: Google Drive accounts of 100 GB and rented SSH servers of 600 GB, or a USB drive in person. KELA lists WinSCP and Rclone for file movement; GuidePoint says no WinSCP or Rclone use appears in the chats. Both detections are included in this folder for that reason, marked as leads. Techniques: T1005, T1567.002, T1052.001.

### Stage 7: extortion and the money

Each victim moves through CHAT, OFFER, CONTRACT and GOLD, the last meaning a payment entry. GuidePoint counts 50 organisations from 2026-02-06 to 2026-09-24, with 27 payment entries totalling about USD 206.95M: 10 of USD 10M or more (USD 166.0M), 8 between USD 1M and 10M (USD 36.9M) and 9 under USD 1M (USD 4.05M). By month the claims are April USD 13.55M, May USD 78.9M, June USD 25.5M, July none, August USD 21M and September USD 68M. Of 16 victims with several offers, 15 ended higher. Every figure is the group's own and unverified. A New York firm authorised USD 1M but demanded proof of deletion, citing a prior group's failure to delete data after payment (The Record). The chats also discuss coercion beyond extortion; the sources describe these as plans and brainstorming, and The Record could not verify the most extreme schemes. Technique: T1657.

### Sleepless Threat

From April 2026 a senior user discussed relaunching under a new brand, described in the chats as a way to become a movement; the Sleepless Rocket.Chat server appears from 2026-09-02 and candidate brand domains were discussed the same day, though GuidePoint says registration is not confirmed. The Record notes a joke that the Russian Ministry of Defense could pay and a May discussion about recruiting sailors near naval bases; the archive shows no evidence of contact, payment or recruitment, and GuidePoint draws no link to a state actor.

### Source conflicts, not resolved here

| Topic | Source A | Source B |
|---|---|---|
| Tools | KELA: Zoom, Teams, Quick Assist, WinSCP, Rclone | GuidePoint: AnyDesk, Zoho, Quick Assist; no WinSCP or Rclone in the chats; GuidePoint is internally inconsistent on Quick Assist (appendix lists it, body treats it as a possible reading of one tag) |
| Bitcoin addresses | KELA: 62 unique addresses | GuidePoint: 65 distinct addresses |
| Leak date | The Record: posted in early October, reported 2026-10-08 | KELA: publicly reported 2026-10-07; GuidePoint: export received 2026-10-06 |
| Date range | KELA: August 2025 to September 2026 | GuidePoint: 2025-08-27 to 2026-09-29 |
| Money | Ledger claim about USD 206.95M | Wallets in the chats received about 37 BTC (about USD 3M), per Crystal Intelligence via KELA |
| Alias | The Record: Chatty Spider | KELA, GuidePoint: Luna Moth |

## Detection strategy

There is no sample, no exploit and no network protocol to fingerprint. The intrusion is a phone call, a legitimate tool and a person. Detection therefore rests on three things: a tool starting where it has never run, a removable drive appearing on a high-value endpoint, and mail or traffic tied to look-alike or published infrastructure.

### Telemetry that matters

- Sysmon Event ID 1 (process creation) and Defender `DeviceProcessEvents` for the first execution of Quick Assist, AnyDesk, Zoho Assist, Syncro, Atera, Splashtop, rclone and WinSCP.
- Sysmon Event ID 22 (DNS query) and Defender `DeviceNetworkEvents` for the published domains and IP addresses, and for the Quick Assist service host.
- Windows Security Event ID 6416 and Defender `DeviceEvents` `UsbDriveMounted` for removable media on executive, partner and assistant endpoints.
- `EmailEvents` for sender domains that combine your name with IT words, and PDF attachments with no links.
- Telephony records: PBX and Teams call logs for inbound calls to executives and assistants, voicemail metadata.
- Badge, visitor and contractor logs, matched to the device events above.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [sigma/01_srg_quick_assist_launched.yml](./sigma/01_srg_quick_assist_launched.yml) | Quick Assist process start; first-seen aggregation in the SIEM |
| Sigma | [sigma/02_srg_anydesk_or_zoho_assist_executed.yml](./sigma/02_srg_anydesk_or_zoho_assist_executed.yml) | AnyDesk or Zoho Assist process start |
| Sigma | [sigma/03_srg_rclone_copy_or_sync_command_line.yml](./sigma/03_srg_rclone_copy_or_sync_command_line.yml) | rclone with copy, sync, move or copyto |
| Sigma | [sigma/04_srg_winscp_remote_transfer_command_line.yml](./sigma/04_srg_winscp_remote_transfer_command_line.yml) | WinSCP with a protocol URL, command or script |
| Sigma | [sigma/05_srg_dns_query_leak_infrastructure_domains.yml](./sigma/05_srg_dns_query_leak_infrastructure_domains.yml) | DNS query for the published domains |
| Sigma | [sigma/06_srg_network_connection_leak_infrastructure_ips.yml](./sigma/06_srg_network_connection_leak_infrastructure_ips.yml) | Outbound connection to the six published IP addresses |
| Sigma | [sigma/07_srg_dns_query_quick_assist_service.yml](./sigma/07_srg_dns_query_quick_assist_service.yml) | Quick Assist service lookup; context only |
| KQL | [kql/k1_first_seen_remote_access_tools_on_high_value_endpoints.kql](./kql/k1_first_seen_remote_access_tools_on_high_value_endpoints.kql) | Tool first seen in the last day against a 90-day baseline |
| KQL | [kql/k2_removable_drive_mount_then_execution_from_drive.kql](./kql/k2_removable_drive_mount_then_execution_from_drive.kql) | USB mount then a process from that drive within 30 minutes |
| KQL | [kql/k3_rclone_winscp_external_transfers.kql](./kql/k3_rclone_winscp_external_transfers.kql) | rclone or WinSCP connections to public addresses |
| KQL | [kql/k4_lookalike_it_sender_domains.kql](./kql/k4_lookalike_it_sender_domains.kql) | Sender domains that mix your name with IT words |
| KQL | [kql/k5_leak_infrastructure_domains_and_ips.kql](./kql/k5_leak_infrastructure_domains_and_ips.kql) | Published domains and IP addresses across 180 days |
| YARA | [yara/srg_leak_infrastructure_strings.yar](./yara/srg_leak_infrastructure_strings.yar) | Published domain and IP strings in text artefacts and transfer configurations (2 rules, no sample available) |
| Suricata | [suricata/srg_leak_infrastructure.rules](./suricata/srg_leak_infrastructure.rules) | DNS, TLS SNI and IP rules for the published infrastructure (sids 6360001 to 6360010) |

No rule claims to detect the call, the lure PDF or the operator. The indicators are retrospective and may have been reassigned, so an infrastructure hit is a lead that needs a date check.

### Threat hunting hypotheses

- **H1.** A remote-access tool the host has never run starts on an executive, partner or assistant endpoint with no help-desk ticket: [hunts/peak_h1_first_seen_remote_tools_on_executive_endpoints.md](./hunts/peak_h1_first_seen_remote_tools_on_executive_endpoints.md).
- **H2.** Mail from a look-alike IT domain, with a PDF that shows a phone number, precedes an inbound call to the same users: [hunts/peak_h2_callback_phishing_and_lookalike_it_domains.md](./hunts/peak_h2_callback_phishing_and_lookalike_it_domains.md).
- **H3.** A removable drive mounts on a high-value endpoint, a tool or file transfer follows, and no visitor record matches: [hunts/peak_h3_usb_insertion_and_unescorted_visitor_activity.md](./hunts/peak_h3_usb_insertion_and_unescorted_visitor_activity.md).

## Incident response playbook

### First 60 minutes (triage)

1. Treat any report of "IT called me and had me start a session" as an incident. Ask the user to stop, disconnect the network and leave the device on; do not reboot.
2. Record the call: caller ID, time, voicemail, the number the user dialled if the lure was a PDF, and what the user said and approved (codes, MFA prompts).
3. Identify the remote tool and the session: process, service, installer, and the time the session started and ended.
4. Isolate the endpoint in EDR and block the tool's service at the proxy and DNS layer for that host.
5. Check what the session reached: file shares, document management systems, cloud drives, mailbox, and the browser's recent uploads.
6. Disable or reset any credential the user typed, read out or approved during the call; revoke active sessions and refresh tokens.
7. Preserve voicemails, emails, caller IDs and remote-session logs; notify counsel and the FBI contact. Do not agree to "do not call the police" framing.
8. If a physical visit is suspected, secure the room, list visitors and contractors for the day and pull badge and camera footage.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| AnyDesk traces | `%ProgramData%\AnyDesk\ad_svc.trace`, `%APPDATA%\AnyDesk\ad.trace` | KAPE, copy with hashes | Session times, remote ID, connection attempts |
| Process execution | Prefetch, Amcache, Shimcache | EZ Tools (PECmd, AmcacheParser, AppCompatCacheParser) | First and last run of the remote tool and anything it launched |
| Event logs | Security, System, Sysmon, PowerShell | EvtxECmd | Service installs, logons, device events |
| USB history | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `%windir%\inf\setupapi.dev.log`, Security 6416 | RECmd, EvtxECmd | Device model, serial, first and last connection |
| Shell and file activity | NTUSER.DAT, UsrClass.dat, Jump Lists, LNK files | SBECmd, JLECmd, LECmd | Folders and documents the operator opened |
| Browser history | Chrome and Edge profile folders | Hindsight, SQLite | Cloud storage uploads and web mail |
| Rclone or WinSCP configs | `%APPDATA%\rclone\rclone.conf`, WinSCP.ini | Copy, YARA | Destination host and credentials |
| Telephony and mail | PBX CDR, Teams call records, mail trace | Export from platform | Link the call to the first tool run |
| Physical records | Badge, visitor, contractor, camera | Facilities export | Match visits to device events |

### IR queries and commands

```powershell
# Author: Jarmi
# Read-only triage on a suspect Windows host: remote-tool traces, services and recent installs.
Get-ChildItem "$env:ProgramData\AnyDesk", "$env:APPDATA\AnyDesk" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'AnyDesk|Zoho|Atera|Splashtop|Syncro|ScreenConnect' } | Select-Object Name, State, PathName
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-14)} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message
```

```bash
# Author: Jarmi
# Find rclone or WinSCP configurations in an acquired image mounted at /mnt/image.
find /mnt/image/Users -iname 'rclone.conf' -o -iname 'WinSCP.ini' 2>/dev/null
grep -rlE '199\.217\.98\.21|216\.203\.20\.157|45\.32\.232\.133' /mnt/image/Users 2>/dev/null
```

```kql
// Author: Jarmi
// Everything one user did in the six hours after a remote tool first ran. Replace the values.
let start = datetime(<add_first_run_time>);
DeviceProcessEvents
| where Timestamp between (start .. start + 6h) and DeviceName =~ "<add_device_name>"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp asc
```

### Containment, eradication, recovery

Exit criteria: the remote tool and any service it installed are removed or confirmed sanctioned; every credential and token exposed during the session is reset; the scope of files read and copied is known from share, DMS and cloud audit logs; counsel has decided on client notification; and no further calls or voicemails from the group are arriving without a handling plan.

What not to do: do not pay or negotiate without counsel and law enforcement; do not assume the group deleted data after payment (GuidePoint notes it may keep copies); do not wipe the endpoint before imaging; do not reply to the operators from the affected user's account.

### Recovery validation

- Re-run the first-seen query (kql/k1) and the infrastructure query (kql/k5) for 30 days and confirm no recurrence.
- Confirm the verification procedure: a callback to a directory number, or a ticket, before any software install or code read-out.
- Test that reception does not transfer callers on request, that visitors are escorted, and that USB device control is enforced on the scoped endpoints.

## IOCs

All indicators come from GuidePoint GRIT Appendix A (2026-10-15) and are retrospective: infrastructure may have been reassigned or abandoned. Full list, 25 rows: [iocs.csv](./iocs.csv). No SHA-256 or other hash exists in the sources, because no sample was recovered.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| domain | aim6umein3kee[.]com | Main Rocket.Chat server | medium | GuidePoint GRIT |
| domain | slplsskdj2836v2jjsx[.]com | Sleepless Rocket.Chat server, from 2026-09-02 | medium | GuidePoint GRIT |
| domain | sokolovsky-law[.]com | Pretext domain, Aug to Sep 2025 | medium | GuidePoint GRIT |
| domain | ominetdata[.]com | Pretext domain, Aug to Sep 2025 | medium | GuidePoint GRIT |
| domain | develevenor[.]com | Pretext domain, Aug to Sep 2025 | medium | GuidePoint GRIT |
| domain | funconnect[.]com | Pretext domain, Aug to Sep 2025 | medium | GuidePoint GRIT |
| domain | sleepless[.]co, sleeplessthreat[.]com, threatactorsneversleep[.]com | Candidate brand domains; registration not confirmed | low | GuidePoint GRIT |
| ipv4 | 45[.]32[.]232[.]133 | RDP host, port 2895 | medium | GuidePoint GRIT |
| ipv4 | 199[.]217[.]98[.]21 | SSH staging server, about 600 GB | medium | GuidePoint GRIT |
| ipv4 | 216[.]203[.]20[.]157 | SSH staging server, about 600 GB | medium | GuidePoint GRIT |
| ipv4 | 87[.]251[.]67[.]222, 87[.]251[.]67[.]223 | Servers delivered with root in Sep 2025; role not stated | low | GuidePoint GRIT |
| ipv4 | 66[.]179[.]31[.]122 | RDP host for the brand social-media account | low | GuidePoint GRIT |
| string | -it.com, it-.com, -law.com | Lookalike domain patterns | low | GuidePoint GRIT |
| note | 3CX PBX on a Netherlands VPS | Telephony for the MAIN model; address not published | medium | GuidePoint GRIT |
| note | 62 (KELA) or 65 (GuidePoint) Bitcoin addresses | Not published; counts differ | medium | KELA, GuidePoint |

KEV: the intrusion itself exploits no vulnerability in any source read. The two CVEs named in the secondary findings were cross-referenced in [kev.md](./kev.md): CVE-2026-104935 (Ivanti Connect Secure) is on CISA KEV, added 2026-10-13, remediation due 2026-10-16, ransomware use unknown; CVE-2026-105445 (Docker Hub) is not on KEV, which does not mean it is safe, since it may be newly disclosed.

## Secondary findings

- **Photon Health and Healthcare Highways (Health-ISAC daily headlines, 2026-10-14).** Photon Health attributes its breach to a zero-day in Metabase and a group using the name Direwolf claims it; Healthcare Highways confirmed an intrusion and data theft, claimed by Chaos; Any-Time Home Care reported a ransomware attack affecting 30,017 people. These come from a headline digest and were not read at the source, so details and attribution need checking. The repo's 2026-06-30 DireWolf case is the earlier coverage of that name.
- **Ivanti Connect Secure, three zero-days chained, one unpatched (same digest).** The headline describes a chain to root in which only two of three flaws have fixes. It is the same family as the CVE-2026-104935 finding in the 2026-10-15 case; no further detail was read.
- **Docker Hub token-transfer flaw (same digest).** Docker patched a critical Docker Hub flaw (CVE-2026-105445, CVSS 9.4 per the headline) that let one user push images as another via transferred access tokens; no exploitation was identified. Headline only.

## Pedagogical anchors

- A tool is not an indicator; the first time a tool runs on a host that has never run it is. Build the baseline per host class, not per organisation.
- Out-of-band verification (a ticket or a callback to a directory number) defeats the whole workflow, and costs one minute. Publish it as policy before the call arrives.
- Malware-free intrusions leave the endpoint nearly empty; your evidence is in telephony, mail, badge and device-control logs, so make sure they are retained and joinable.
- Read a leak as unverified intelligence: three vendors disagree on tools, address counts and dates, and the claimed USD 206.95M sits next to about 37 BTC on-chain. Record conflicts instead of resolving them by instinct.
- Physical security belongs in the threat model of a law firm: escorts, visitor logs, USB control and reception scripts are detections too.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram (Template A). | [kill_chain.svg](./kill_chain.svg) |
| kev.md | CISA KEV cross-reference for this case's CVEs. | [kev.md](./kev.md) |
| iocs.csv | 25 rows of retrospective infrastructure indicators, patterns and notes. | [iocs.csv](./iocs.csv) |
| sigma/ | Seven Sigma rules for remote tools, transfer tools and published infrastructure. | [sigma/](./sigma/) |
| kql/ | Five Defender XDR queries for first-seen tools, USB, transfers, look-alike senders and infrastructure. | [kql/](./kql/) |
| yara/srg_leak_infrastructure_strings.yar | Two YARA rules for published strings in text artefacts and transfer configs. | [yara/srg_leak_infrastructure_strings.yar](./yara/srg_leak_infrastructure_strings.yar) |
| suricata/srg_leak_infrastructure.rules | Ten Suricata rules, sids 6360001 to 6360010. | [suricata/srg_leak_infrastructure.rules](./suricata/srg_leak_infrastructure.rules) |
| hunts/ | Three PEAK hunts (H1 to H3). | [hunts/](./hunts/) |

## Sources

- [Silent Ransom Group (SRG) Chat Leak Analyzed — KELA, 2026-10-13](https://www.kelacyber.com/blog/silent-ransom-group-chat-leak-analyzed/)
- [Behind the Help Desk Call: Insights from the Leaked Chats of an IT-Impersonation Extortion Crew — GuidePoint GRIT, 2026-10-15](https://www.guidepointsecurity.com/blog/silent-ransom-group-leaked-chats/)
- [Leaked chats show Russian extortion gang sending agents into US law firms — The Record, 2026-10-08](https://therecord.media/leaked-chats-show-russian-extortion-gang-sending-agents-to-law-firms)
- [Health-ISAC Daily Cyber Headlines, 2026-10-14 (secondary findings, headline level)](https://health-isac.org/wp-content/uploads/TLP-WHITE-Daily-Cyber-Headlines-10.14.2026.pdf)
- Repo context: the SRG / Luna Moth fast flux case of 2026-06-24 in `days/2026/06/`.

The sources were read through automated page summaries, not in a browser. KELA's full report (Bitcoin list, role breakdown) is gated and was not read; indicators and figures should be checked against the original pages before they are used for blocking or reporting.
