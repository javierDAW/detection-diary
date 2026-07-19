# PEAK Hunt H3 -- Native LOLBin Used to Tamper Windows Defender Outside Maintenance

**Case:** INC Ransom / City of Acworth, GA (2026-07-19)
**MITRE:** T1685 (Disable or Modify Tools)

## Hypothesis

INC Ransom operators use the native, Microsoft-signed `SystemSettingsAdminFlows.exe`
utility to disable Windows Defender ahead of the encryptor run. If present here, we
should find invocations of this (or functionally similar native) LOLBins touching
Defender configuration outside of any scheduled maintenance or MDM/Intune baseline
push window.

## Abstract

Enumerate all executions of `SystemSettingsAdminFlows.exe` fleet-wide, plus a
secondary sweep for direct Defender-tamper primitives (`Set-MpPreference`,
`MpCmdRun.exe -RemoveDefinitions`, registry writes to
`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`). Cross-
reference the timestamp and initiating account against your MDM/Intune change log;
anything unaccounted for is a hunt lead.

## Execute

```kql
DeviceProcessEvents
| where FileName =~ "SystemSettingsAdminFlows.exe"
| where ProcessCommandLine has_any ("Defender","RemoveDeviceGuard","WindowsDefenderApp")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```

```kql
DeviceRegistryEvents
| where RegistryKey has @"Policies\Microsoft\Windows Defender"
| where RegistryValueName =~ "DisableAntiSpyware" and RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessAccountName
```

## Key results

Record: device, initiating account, whether the account is a known
MDM/Intune/GPO service account or an interactive/compromised-looking identity,
and whether the change correlates with any other stage-artifact on the same host
(recon tools, PsExec/winupd, archive utilities).

## Interpret

True positive: Defender-tamper action by a non-management account, outside a
known change window, co-located in time with other kill-chain artifacts on the
same host. False positive: a legitimate security-tooling exclusion pushed via
Intune/GPO with a matching audit trail -- close the lead once the change-
management record is confirmed.
