# PEAK Hunt H1 -- PsExec-Derived Services Named Like Windows Updates

**Case:** INC Ransom / City of Acworth, GA (2026-07-19)
**MITRE:** T1036.005 (Match Legitimate Resource Name), T1569.002 (Service Execution)

## Hypothesis

INC Ransom operators install a PsExec-derived binary as a demand-start LocalSystem
service under a name that mimics a legitimate Windows update artifact (documented
case: `winupd.exe`, Event ID 7045). If this group's playbook applies here, we should
find one or more hosts across the fleet with a recently-installed service whose
binary path or name resembles a Windows-update process but does not match the
known-good WSUS/Windows Update Agent binary set.

## Abstract

Pull Windows Security/System Event ID 7045 (service installed) fleet-wide for the
trailing 30 days. Filter to services whose `ImagePath` contains update-sounding
strings (`winupd`, `wuauclt`-lookalikes, `update`) but whose path is NOT one of the
known Microsoft-signed Windows Update binaries, and whose start type is
demand-start under LocalSystem -- an unusual combination for a legitimate update
component, which typically runs as a scheduled/automatic service.

## Execute

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 5000 |
  Where-Object { $_.Message -match 'update' -or $_.Message -match 'winupd' } |
  Select-Object TimeCreated, MachineName, Message
```

```kql
DeviceProcessEvents
| where FileName =~ "winupd.exe" or (FileName has "update" and FolderPath !has "WinSxS" and FolderPath !has "servicing")
| where InitiatingProcessFileName in~ ("services.exe","svchost.exe")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```

## Key results

Record: hostname, service name, ImagePath, code-signing status (should be unsigned
or signed by an unexpected publisher), install timestamp, and installing account.
A cluster of installs across many hosts within a short window (minutes to low
hours) is the strongest signal -- legitimate patch tooling stages over a much
longer maintenance window and is centrally orchestrated (SCCM/Intune/WSUS), not
locally installed host-by-host.

## Interpret

True positive: unsigned or unexpectedly-signed binary, LocalSystem demand-start
service, installed outside any known change window, on multiple hosts in rapid
succession. False positive: a legitimate but unusually-named internal deployment
tool -- verify with the endpoint owner and check for a matching change ticket
before escalating.
