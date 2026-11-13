# PEAK hunt H3 - DCSync from a workstation, Rclone to SFTP from file servers, and privileged accounts that containment cannot touch

## Prepare

- **Hypothesis:** after obtaining certificates for privileged accounts, the attacker replicated secrets from a domain controller (DCSync) from a non-DC host, then used a privileged account that was excluded from automatic containment to reach a file server, where a renamed Rclone binary copied shares to an external SFTP server.
- **Why:** Microsoft Security Research (2026-10-30): DCSync ran within seconds of the first certificate; one privileged account was excluded from Defender automatic attack disruption and remained usable; on a file server a renamed Rclone (`SearchApp.exe`) copied a share recursively to external SFTP with 20 concurrent transfers, files up to about 3 years old, excluding executables, databases, virtual disks, media, temp and log types. More than 1,000 later SMB/logon attempts were blocked by disruption.
- **Honesty:** the SFTP host, Rclone command line, remote name, file server name and the excluded account are NOT published. The 4662 GUIDs, Rclone flags and audit settings are generic knowledge. Microsoft's hunting queries were not available.
- **Scope:** DC Security logs (4662, 4624) for 30 days; `DeviceProcessEvents` / `DeviceNetworkEvents` on all file servers; firewall / proxy logs for outbound tcp/22; the Defender automatic attack disruption exclusion list and any other "do not contain" lists (EDR exclusions, PAM break-glass).
- **Confidence:** high for replication rights exercised from a non-DC IP by a non-sync account; medium-high for Rclone (any name) talking SFTP from a file server; process-name-only hits on `SearchApp.exe` are worthless (legitimate Windows process).

## Execute

**Data sources / content:** `sigma/05_dcsync_replication_rights_by_non_machine_account.yml`, `sigma/03_rclone_sftp_copy_or_renamed_rclone_binary.yml`, `kql/k3_adcs_esc1_esc8_certificate_issuance_pkinit_and_dcsync.kql` (section 4), `suricata/helpdesk_impersonation_adcs_esc8_exfil_heuristics.rules` (sid 9993001), `yara/bun_runtime_and_renamed_rclone_hunting.yar` (rule 2).

1. Make sure DCSync is visible: `auditpol /get /subcategory:"Directory Service Access"` on DCs and a SACL auditing the replication extended rights on the domain NC. Then list who legitimately holds the rights (read-only):

```powershell
# Author: Jarmi
$dn = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:$dn").Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c') } |
  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType | Sort-Object IdentityReference -Unique
```

2. Run k3 section 4 (`DcSyncFromNonDcIp`); every row whose `LogonIp` is a workstation is an incident. Line it up with the certificate timeline from H2 - Microsoft saw seconds between certificate and DCSync.
3. Find Rclone regardless of name on file servers: Sigma 03 renamed-binary selection, plus `DeviceProcessEvents | where ProcessVersionInfoOriginalFileName =~ "rclone.exe" and FileName !~ "rclone.exe"`, plus outbound tcp/22 from file servers in `DeviceNetworkEvents` or the firewall. On a suspect server scan the profile, temp and ProgramData trees with YARA rule 2 and look for an `rclone.conf` (an `sftp` remote reveals the destination).

```powershell
# Author: Jarmi
Get-ChildItem C:\Users\*\AppData\Roaming\rclone\rclone.conf, C:\Users\*\.config\rclone\rclone.conf -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'SearchApp.exe' -and $_.ExecutablePath -notlike 'C:\Windows\SystemApps\*' } |
  Select-Object ProcessId, ExecutablePath, CommandLine
```

4. Inventory every account excluded from automatic containment (Defender automatic attack disruption exclusions, EDR "do not isolate" lists) and check the logons of those accounts in the incident window - an attacker holding a certificate for an excluded privileged account keeps working while everything else is contained.

## Act

- **Expected benign:** Entra Connect / sync accounts and identity tools with replication rights; approved backup or migration jobs using Rclone (normally named `rclone.exe`, known service account, known remote).
- **Action on match:** DCSync from a workstation means assume full domain credential compromise: double krbtgt rotation, reset all privileged and service accounts, revoke rogue certificates and purge tickets (revocation alone does not kill issued TGTs). For Rclone: block the SFTP destination at egress, isolate the file server, preserve `rclone.conf` and the binary, and scope what was copied using file access telemetry (Rclone's 3-year age filter narrows the candidate set).
- **Hardening:** keep exclusions from automatic containment to the minimum and time-bound them, block outbound SSH/SFTP from servers by default, and alert on any 4662 replication from non-DC IPs.
- **Exit criteria:** no replication rights holders beyond DCs and documented sync accounts; no Rclone (any name) on servers outside approved jobs; every excluded account reviewed and justified.
