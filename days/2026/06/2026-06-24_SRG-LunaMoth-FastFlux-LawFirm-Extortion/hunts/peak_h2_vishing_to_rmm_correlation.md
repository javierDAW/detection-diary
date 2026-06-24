# PEAK Hunt H2 — Vishing-to-RMM Timeline Correlation

## Hypothesis

A workstation in the environment received an inbound phone call or participated in a VoIP call,
and within 60 minutes the same workstation installed or executed a signed RMM tool from a
user-writable path. This sequence is the canonical SRG / Luna Moth initial access pattern.

## Prepare

**Relevant telemetry**: 
- Process creation logs (Sysmon EID 1 / EID 4688 / Defender XDR DeviceProcessEvents)
- VoIP / softphone call logs (Microsoft Teams call records, Zoom CDR, 3CX CDR)
- MDM / IT asset management logs (Intune — non-baseline software install events)

**Scope**: All Windows workstations, 14-day lookback. Law firm and legal department hosts are highest priority.

## Execute

**Step 1 — RMM installs from user-writable paths (Defender XDR)**:
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ (
    "ScreenConnect.WindowsClient.exe","ScreenConnect.ClientService.exe",
    "zohoassist.exe","ITSPlatform.exe","itarian.exe","AnyDesk.exe"
  )
| where FolderPath has_any (@"Downloads", @"AppData\Local\Temp", @"Users\Public", @"Desktop")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

**Step 2 — Cross-reference with Teams call records (Microsoft Graph / Purview)**:
```
If Teams/Zoom/3CX CDR is available:
- Extract inbound call events to the same user/device as Step 1
- Filter calls within 60 minutes before the RMM install timestamp
- A match of (inbound_call_time + 0..60min = RMM_install_time) on the same device is the signal
```

**Step 3 — Intune non-baseline software detection**:
```kql
// If Intune/MEM logs are ingested into Sentinel:
IntuneDeviceComplianceLogs
| where TimeGenerated > ago(14d)
| where AppName has_any ("ScreenConnect","Zoho Assist","ITarian","AnyDesk")
| where AppInstallStatus == "Installed"
    and AppInstallSource has_any ("UserDownload","Unknown")
| project TimeGenerated, DeviceName, UserName, AppName, AppVersion, AppInstallSource
```

## Analyze

- Presence of a non-baseline RMM install from a user download path is HIGH priority regardless of VoIP correlation.
- The VoIP timeline correlation elevates this to CRITICAL — it demonstrates the social engineering step occurred.
- Note: SRG victims report calls lasting 5–30 minutes; actor guides victim step by step through the installation.
- If the RMM was installed but no subsequent large network transfer occurred, the actor may have been interrupted
  or the vishing call was abandoned (still warrants investigation and RMM removal).

## Report

- Escalate any confirmed vishing-to-RMM timeline to IR immediately.
- Collect: process creation timeline, RMM session logs, VoIP call recording (if available), DNS cache, network flow.
- Remove RMM tool, reset user credentials, audit file access during the session window.

## References

- [FBI IC3 Flash 260526](https://www.ic3.gov/CSA/2026/260526.pdf)
- [SecurityWeek SRG DNS Fast Flux](https://www.securityweek.com/silent-ransom-group-uses-dns-fast-flux-in-attacks/)
