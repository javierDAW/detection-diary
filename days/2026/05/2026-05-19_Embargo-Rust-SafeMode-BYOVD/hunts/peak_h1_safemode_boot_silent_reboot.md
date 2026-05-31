# PEAK H1 — Silent Safe Mode reboot outside maintenance window (Embargo MDeployer T1562.009)

## Hypothesis

An Embargo affiliate has staged MDeployer on a host and triggered a reboot
into Safe Mode with Network to disable the locally installed AV/EDR before
running the ransomware payload. The host will register a persistence service
named `irnagentd` (or rotated name) under
`HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Network\` and execute
`bcdedit /set {default} safeboot Minimal` followed by `shutdown -r -f -t 00`.

## Why this discriminates

Legitimate Safe Mode reboots are rare and almost always part of a documented
troubleshooting session. The combination of `bcdedit safeboot Minimal`
**plus** a new entry under `\Safeboot\Network\` **plus** an immediate forced
shutdown is operationally unique to ransomware operators and a small handful
of advanced persistence techniques. None of the BYOVD ransomware cases
catalogued in this repo previously used T1562.009 — Embargo is the first.

## Expected benign vs malicious

| Signal | Benign | Malicious |
|---|---|---|
| `bcdedit /set {default} safeboot Minimal` | Manual troubleshooting in a maintenance window; documented change ticket | Triggered by `cmd.exe` spawned from `rundll32.exe` or a scheduled task with unusual principal |
| `\Safeboot\Network\<name>` write | None on production hosts; very rare on developer hosts when testing custom services | `irnagentd` or rotated name with `binpath` pointing to `C:\Windows\Debug\` or `C:\Windows\` |
| `shutdown -r -f -t 00` immediately after | Operator pressing Restart Now in error message | Triggered programmatically with no preceding logon session change |

## Action on match

1. EDR isolate the host immediately.
2. Acquire RAM before any reboot completes.
3. Snapshot the `HKLM\SYSTEM\CurrentControlSet\Control\Safeboot` subtree.
4. Hash and quarantine any non-canonical-path drivers under
   `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`.
5. Pivot to H2 (BYOVD driver-load burst) and H3 (`C:\Windows\Debug\` writes)
   on the same host.

## Queries

### Defender XDR — bcdedit safeboot followed by scheduled task or service creation

```kql
let WindowMin = 10m;
let Bcdedit = DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName =~ "bcdedit.exe"
  | where ProcessCommandLine has "safeboot" and ProcessCommandLine has "Minimal";
let SafebootRegWrite = DeviceRegistryEvents
  | where Timestamp > ago(7d)
  | where RegistryKey has @"\Safeboot\Network\"
  | where ActionType in ("RegistryValueSet", "RegistryKeyCreated");
Bcdedit
| join kind=inner (SafebootRegWrite) on DeviceId
| where datetime_diff('minute', Timestamp1, Timestamp) between (0 .. (WindowMin / 1m))
| project Timestamp, DeviceId, DeviceName, BcdeditCmd = ProcessCommandLine, RegKey = RegistryKey, RegValue = RegistryValueName
```

### Sysmon EID 1 — same chain on raw Sysmon

```text
EventID:1 (Image="*\bcdedit.exe" AND CommandLine:"*safeboot*" AND CommandLine:"*Minimal*")
| join EventID:13 (TargetObject:"*\\Safeboot\\Network\\*") within 10m on Computer
```

### Local registry sweep (PowerShell)

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Safeboot\Network' |
    Where-Object { $_.PSChildName -notin @('AppMgmt','EventLog','BFE','DcomLaunch','Dhcp','RpcSs') } |
    Select-Object PSChildName
```

## False positives to triage

- Custom enterprise recovery tools occasionally register a Safe Mode service.
  These should be inventoried; any new entry not in the inventory is a hit.
- Developer workstations where Safe Mode boot is used for kernel-driver
  debugging. Should always be documented in a change ticket.
