# PEAK Hunt H2 — GentlemenCollection Staging: IOC-Agnostic Pre-Encryption Artifact

## Hunt Type
Indicator-driven / low frequency

## Hypothesis
Every Gentlemen affiliate intrusion observed by ESET deployed EDR killers to a directory
named `GentlemenCollection` regardless of which variant was used. Hunting for this string
in filesystem artifacts, process command lines, and Windows Event Logs provides an
IOC-agnostic detection that survives driver rotation and packer updates.

## Rationale
The staging directory `GentlemenCollection` is the most durable behavioral anchor in the
entire Gentlemen toolkit. It appears in file paths, command lines, and service names.
It predates the EDR kill and encryption phases by minutes to hours, giving defenders a
response window not available from post-kill telemetry. ESET confirmed this pattern
across all investigated Gentlemen intrusions since February 2026.

## Data Sources
- Defender XDR: DeviceFileEvents, DeviceProcessEvents
- Windows Event Log: Security 4663 (file access audit), System 7045 (service install)
- PowerShell ScriptBlock logs (EID 4104): if staging uses PowerShell copy
- MFT forensics (post-incident): $MFT entry for GentlemenCollection directory

## Hunt Query (KQL)

```kql
// Filesystem artifact
let FileHits = DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "GentlemenCollection" or FileName has "GentlemenCollection"
| extend HitSource = "FileEvent"
| project Timestamp, DeviceName, HitSource, Detail = strcat(FolderPath, "\\", FileName),
    InitiatingProcessCommandLine;

// Process command line artifact
let ProcHits = DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "GentlemenCollection" or
        InitiatingProcessCommandLine has "GentlemenCollection"
| extend HitSource = "ProcessCommandLine"
| project Timestamp, DeviceName, HitSource,
    Detail = coalesce(ProcessCommandLine, InitiatingProcessCommandLine),
    InitiatingProcessCommandLine;

// Registry artifact (service or run key referencing staging dir)
let RegHits = DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryValueData has "GentlemenCollection"
| extend HitSource = "RegistryValue"
| project Timestamp, DeviceName, HitSource,
    Detail = strcat(RegistryKey, " -> ", RegistryValueData),
    InitiatingProcessCommandLine;

// Union and triage
union FileHits, ProcHits, RegHits
| order by Timestamp desc
```

## Expected Output
Any hit on `GentlemenCollection` across file, process, or registry telemetry within the
last 30 days. Even a single historical file event warrants investigation — this string
has no legitimate software use.

## Forensic Artifact Checklist
If a live match is found, collect immediately:
- MFT entry for `GentlemenCollection` directory (creation timestamp, parent MFT)
- Contents of the directory (driver .sys files, EDR-killer EXEs)
- $UsnJrnl records around the directory creation time window
- Prefetch for any EXE dropped in or run from GentlemenCollection

## Response Threshold
Single match = escalate to IR. No additional confirmation needed.
