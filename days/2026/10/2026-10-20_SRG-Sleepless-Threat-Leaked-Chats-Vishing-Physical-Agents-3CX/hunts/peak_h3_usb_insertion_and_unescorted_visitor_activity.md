# PEAK hunt H3 - USB insertion and unescorted visitor activity on high-value endpoints

## Prepare

**Hypothesis.** If a person posing as IT staff reaches an endpoint in person (the fallback described by the FBI and discussed in the chats), then a removable drive mounts on an executive, partner or assistant endpoint during or just outside office hours, a remote-access tool or an unknown executable runs from that drive within minutes, or files are copied to the drive, and the visit does not match a ticket or a badge record.

**Why third.** It is the rarest path and the least covered by tools. The Record reports a New York firm whose letter described files copied to a flash drive in its office.

**Scope.** High-value endpoints, 14 days; badge and visitor logs, reception records and cleaning or delivery contractor schedules for the same period.

**Data quality check first.** Confirm that device control logs (UsbDriveMounted, Windows Event ID 6416 for new external devices) reach the SIEM, and that visitor logs can be matched to floors and times.

## Execute

```kql
// Full query in kql/k2. A drive mounts, then a process runs from that drive within 30 minutes.
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "UsbDriveMounted"
| project Timestamp, DeviceName, AdditionalFields
```

```powershell
# Author: Jarmi
# USB device history on a suspect Windows host (read-only): first and last connection and the serial.
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue | Select-Object FriendlyName, PSChildName
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=6416; StartTime=(Get-Date).AddDays(-14)} -ErrorAction SilentlyContinue | Select-Object -First 30 TimeCreated, Message
Select-String -Path "$env:windir\inf\setupapi.dev.log" -Pattern 'USBSTOR' -ErrorAction SilentlyContinue | Select-Object -Last 20
```

## Act

1. Match each external-device event with badge, visitor and contractor records; an event with no matching visit is the lead.
2. Image the drive's trace on the host (USBSTOR, setupapi, shellbags, recent files) before any cleanup.
3. Treat unannounced "IT" visitors, deliveries and cleaners as unverified until confirmed by the real IT contact; test whether escort rules are followed.
4. Report to law enforcement; GuidePoint advises against accepting a "do not call the police" framing.

## Knowledge

- GuidePoint reports that much of the physical and coercive activity has no Enterprise ATT&CK technique and suggests modelling it with physical-security and insider-threat frameworks.
- The recruiting side (job ads for drivers, promoters or security) can be reported to platform trust-and-safety teams.
