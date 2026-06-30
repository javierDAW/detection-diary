# PEAK Hunt H3 — Dire Wolf note / marker / forced-reboot co-occurrence

**Hypothesis (P).** Near the end of a Dire Wolf run, a host will show a burst of `HowToRecoveryFiles.txt` writes and `.direwolf` renames co-occurring with creation of `C:\runfinish.exe` and a `shutdown -r -f -t 10` command.

**Why it works.** These are the impact and post-impact artifacts. Even though the binary self-deletes, the marker, notes and forced-reboot command remain visible in file and process telemetry and confirm the family and completion state.

**Enrich (E).** Join file-event telemetry (note + marker + extension) with process-creation telemetry (`shutdown.exe -r -f`).

```kql
let files =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "HowToRecoveryFiles.txt" or FileName endswith ".direwolf" or (FolderPath endswith "\\runfinish.exe" and FolderPath startswith "C:\\")
    | summarize fileHits=count(), firstFile=min(Timestamp), lastFile=max(Timestamp) by DeviceName, bin(Timestamp,10m);
let reboot =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "shutdown.exe" and ProcessCommandLine has "-r" and ProcessCommandLine has "-f"
    | summarize rebootCmd=any(ProcessCommandLine), rebootTime=min(Timestamp) by DeviceName, bin(Timestamp,10m);
files | join kind=inner reboot on DeviceName, Timestamp
```

**Analyze (A).** Co-occurrence in the same 10-minute bin confirms Dire Wolf impact on that host. Use the earliest H1 host as patient zero, not the first host to show notes.

**Knowledge (K).** Preserve memory and the marker/notes on any host caught before the reboot; the sample will be gone afterward. Feed confirmed hosts back into containment scoping.
