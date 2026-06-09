# PEAK Hunt H1 — recovery-inhibition command burst

**Hypothesis.** If the Kyber Windows encryptor ran with elevation on a host, then that host will show several distinct anti-recovery actions in a tight window: Volume Shadow Copy deletion via three methods (WMI `Win32_ShadowCopy` delete, `wmic shadowcopy delete`, `vssadmin Delete Shadows`), `bcdedit recoveryenabled No` / `bootstatuspolicy ignoreallfailures`, `wbadmin DELETE SYSTEMSTATEBACKUP`, and `wevtutil cl` over all channels.

**ATT&CK.** T1490 (Inhibit System Recovery), T1562.001 (Impair Defenses), T1070.001 (Clear Windows Event Logs).

## Prepare

- Telemetry: Sysmon EID 1 or Security 4688 (process creation with command line), or Defender `DeviceProcessEvents`.
- Scope: file servers, backup servers, and hypervisor hosts first. Baseline scheduled backup/maintenance jobs that legitimately prune shadow copies.

## Execute

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| extend Cmd = tolower(ProcessCommandLine)
| extend Action = case(
    FileName =~ "vssadmin.exe" and Cmd has "delete" and Cmd has "shadows", "vssadmin",
    FileName =~ "wmic.exe" and Cmd has "shadowcopy" and Cmd has "delete", "wmic_vss",
    Cmd has "win32_shadowcopy" and Cmd has "delete", "wmi_vss",
    FileName =~ "bcdedit.exe" and (Cmd has "recoveryenabled" or Cmd has "bootstatuspolicy"), "bcdedit",
    FileName =~ "wbadmin.exe" and Cmd has "systemstatebackup", "wbadmin",
    FileName =~ "wevtutil.exe" and Cmd has " cl", "wevtutil",
    "")
| where isnotempty(Action)
| summarize Actions = make_set(Action, 10), n = dcount(Action) by DeviceName, bin(Timestamp, 1h)
| where n >= 2
| order by n desc
```

## Analyze

- A single host showing 2+ distinct recovery-inhibition actions within an hour is high-fidelity ransomware impact. Three independent VSS-deletion methods on one host is essentially diagnostic of an automated encryptor.
- Pivot positives to H2 (backup/AV/SQL service stops) and check for the `MaxMpxCt` registry change and `.#~~~` files to confirm Kyber specifically.

## Act

- If confirmed: isolate the host, preserve memory and a binary sample, and immediately verify the status of immutable/off-host backups before any restore.
- Re-enable the Windows Recovery Environment and re-establish VSS/backup schedules during recovery; rotate credentials for backup, hypervisor, and domain accounts.
