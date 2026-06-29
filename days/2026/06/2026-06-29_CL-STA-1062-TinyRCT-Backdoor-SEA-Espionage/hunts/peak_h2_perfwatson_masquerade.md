# PEAK Hunt H2 — PerfWatson2.exe running from the wrong place

**Hypothesis.** The TinyRCT backdoor masquerades as the Visual Studio telemetry binary
`PerfWatson2.exe` but enforces an execution-location guard requiring `%LOCALAPPDATA%`
(T1036.005). Any `PerfWatson2.exe` process whose image path is under `AppData` rather than
`Program Files` is suspect.

**ABLE breakdown.**
- **Actor:** CL-STA-1062.
- **Behavior:** name-collision masquerade anchored on execution path.
- **Location:** `%LOCALAPPDATA%` on compromised Windows hosts.
- **Evidence:** `DeviceProcessEvents` (Defender XDR), Sysmon EID 1.

**Data sources.** Defender XDR `DeviceProcessEvents`; Sysmon Event ID 1.

**Hunt logic (Defender XDR).**
```kql
DeviceProcessEvents
| where FileName =~ "PerfWatson2.exe"
| where FolderPath has_any (@"\AppData\Local\", @"\AppData\Roaming\")
| where not(FolderPath has_any (@"\Program Files\", @"\Program Files (x86)\"))
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256
```

**Triage / pivots.**
1. Hash the binary; compare against the published TinyRCT SHA256 and submit unknowns.
2. Inspect network events for the loading host to C2 `45.32.113[.]172` (HTTP, ~10s beacon).
3. Look for a `choice.exe` timer + `del` self-delete shortly after a wipe instruction.

**Expected benign.** None expected; genuine PerfWatson2 runs from Program Files.

**Outcome.** Isolate the host, collect the binary + scheduled task, and feed any new install
path into the Sigma `process_creation` masquerade rule.
