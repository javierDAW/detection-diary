# PEAK Hunt H1 — Recovery inhibition immediately preceding encryption

- **Hypothesis:** An Aur0ra-style filecoder deletes Volume Shadow Copies (and/or disables boot recovery) and then encrypts files within minutes on the same host. Because Aur0ra adds no extension and performs no rename, the VSS-deletion-then-modification-burst sequence is the most reliable end-to-end impact signal.
- **MITRE:** T1490 (Inhibit System Recovery) → T1486 (Data Encrypted for Impact)
- **Data sources:** Defender XDR `DeviceProcessEvents` + `DeviceFileEvents`; Sysmon EID 1 + EID 11; Windows Security 4688.

## Prepare

Baseline which hosts and service accounts legitimately run `vssadmin`, `wmic shadowcopy`, `wbadmin`, or `bcdedit` (backup servers, imaging maintenance windows). Anything outside that set running these is a candidate.

## Execute

```kql
let recovery =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any ("Delete Shadows", "shadowcopy delete", "wbadmin delete catalog", "recoveryenabled no")
    | project RecoveryTime = Timestamp, DeviceName, RecoveryCmd = ProcessCommandLine;
let mods =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType == "FileModified"
    | summarize ModCount = dcount(FolderPath), BurstTime = min(Timestamp)
              by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
    | where ModCount > 200;
recovery
| join kind=inner mods on DeviceName
| where BurstTime between (RecoveryTime .. (RecoveryTime + 30m))
| project DeviceName, RecoveryTime, RecoveryCmd, BurstTime, InitiatingProcessFileName, ModCount
| order by RecoveryTime desc
```

## Act / Analyze

A match is a near-certain in-progress or completed ransomware event: isolate the host, capture memory before killing the process, and pivot to the ransom-note sweep (H2). Promote the join logic to a scheduled analytic. If no match but recovery deletion fired alone, still triage — deletion is rarely benign on a workstation.
