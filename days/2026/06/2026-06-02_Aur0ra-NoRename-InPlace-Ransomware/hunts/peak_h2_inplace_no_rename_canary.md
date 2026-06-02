# PEAK Hunt H2 — In-place encryption with no rename (canary-aware)

- **Hypothesis:** A single non-system process modifies a large number of files across local and mapped drives **without** any matching rename/extension-change events. This is the defining behaviour of Aur0ra and of the broader no-rename filecoder trend, and it is invisible to controls that key on extension changes or "file was renamed" canary triggers.
- **MITRE:** T1486 (Data Encrypted for Impact)
- **Data sources:** Defender XDR `DeviceFileEvents` (`FileModified` vs `FileRenamed`); EDR file-I/O telemetry; FSRM / canary file last-write + hash.

## Prepare

Identify legitimate high-volume file modifiers (sync clients, backup, indexing, AV) and exclude them. Deploy canary files in monitored shares/user dirs and record their hash + last-write — explicitly alert on **content change**, not rename or delete.

## Execute

```kql
// Processes producing a modification burst with no corresponding rename activity
let renamers =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileRenamed"
    | distinct DeviceName, InitiatingProcessId = InitiatingProcessId, InitiatingProcessFileName;
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileModified"
| where InitiatingProcessFolderPath !startswith "C:\\Windows\\"
| where InitiatingProcessFileName !in~ ("OneDrive.exe","MsMpEng.exe","SearchIndexer.exe","Dropbox.exe")
| summarize ModCount = dcount(FolderPath), Files = make_set(FileName, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessSHA256
| where ModCount > 200
| join kind=leftanti renamers on DeviceName, InitiatingProcessId, InitiatingProcessFileName
| order by ModCount desc
```

## Act / Analyze

A high-modification, zero-rename process is the strongest in-place-encryptor signal. Validate against canary content changes. Isolate, capture memory, and confirm with the ransom-note sweep. Feed confirmed process hashes back to the EDR block list, but keep the behavioural rule primary — the hash will change on the next sample.
