# PEAK Hunt H2: Mass Backup/Database/Hypervisor Service-Stop Burst

**Author:** Jarmi
**Date:** 2026-07-21
**Case:** Spirals ransomware
**Hypothesis type:** Intelligence-based hunt (pre-ransomware objective)

## Hypothesis

*If* an attacker is staging for ransomware deployment, *then* a burst of
`Stop-Service` (or equivalent SCM stop) calls against backup, database, and
hypervisor-named services will occur within a tight time window, minutes
before the encryption payload is deployed — because open file handles held
by those services must be released before the encryptor can touch the
underlying data files.

## Why this matters

This is the single latest point in the Spirals kill chain where the attack
is still reversible: the service-stop sweep is a necessary precondition,
not an afterthought, and it is executed as one broad automated pass rather
than being hidden or staggered. A detection here buys defenders the last
few minutes before irreversible data loss.

## Data sources

- Windows System event log, Service Control Manager source, Event IDs 7036
  (service stopped) and 7040 (service start type change)
- PowerShell Script Block Logging (Event ID 4104) for `Stop-Service` and
  `Get-WmiObject Win32_Service` invocations
- EDR process-creation telemetry for `powershell.exe`/`pwsh.exe` command
  lines containing `Stop-Service`

## Procedure

1. Query System EID 7036 fleet-wide for the trailing 14 days, filtering
   `Service Name` against a maintained list of backup/database/hypervisor
   product name fragments (veeam, vmms, vmcompute, commvault, acronis,
   veritas, sql server, oracle, mysql, postgre, exchange, sap, sage, intuit,
   domino).
2. Group matches by host and 5-minute time bucket; flag any host/bucket
   with 3 or more distinct qualifying service-stop events — a legitimate
   maintenance window rarely stops this many unrelated vendors' services
   simultaneously.
3. For any flagged host, pivot to EID 4104 PowerShell script-block logs in
   the same window to confirm whether a `Get-WmiObject Win32_Service |
   Stop-Service` pattern (or equivalent) is present.
4. Cross-reference the flagged host against recent PsExec or WMI
   lateral-movement telemetry (see H3) — Spirals staged this burst
   immediately after mass PsExec deployment.
5. Treat any positive hit as an active incident, not a hunt finding to
   triage later — trigger IR playbook Step 4 (isolate backup infrastructure)
   immediately.

## Expected legitimate activity (false positives)

Scheduled patch-Tuesday maintenance windows that restart multiple services
including some backup agents; these are typically staggered over a longer
window and correlate with a documented change ticket, unlike the
attacker's single tight burst.

## Related detections

`sigma/spirals_mass_backup_service_stop.yml`
