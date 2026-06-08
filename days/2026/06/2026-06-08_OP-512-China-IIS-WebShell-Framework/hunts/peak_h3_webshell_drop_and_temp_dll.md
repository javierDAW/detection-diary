# PEAK Hunt H3 — web shell drop + ASP.NET temporary-compilation DLL

**Hypothesis.** If a polymorphic web shell was deployed, then new `.aspx`/`.ashx`/`.asmx` files will appear in webroot/upload directories and freshly compiled `.dll` artifacts will appear in the ASP.NET temporary compilation directory — outside any deployment window, and persisting after the source is deleted.

**ATT&CK.** T1505.003 (Web Shell), T1027 (Obfuscated Files), T1070.006 (Timestomp).

## Prepare

- Telemetry: Sysmon EID 11 (file create), Defender `DeviceFileEvents`, file-integrity monitoring on webroot and `Temporary ASP.NET Files`.
- Scope: known deployment windows / release pipelines to exclude. Note the shells **timestomp**, so do not rely on file age for triage.

## Execute

```kql
DeviceFileEvents
| where Timestamp > ago(45d)
| where ActionType in~ ("FileCreated","FileModified")
| extend IsServerScript = (FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx")
| where (InitiatingProcessFileName =~ "w3wp.exe"
         and FolderPath has_any (@"\inetpub\", @"\wwwroot\", @"\uploads\", @"\upload\")
         and IsServerScript)
     or (FolderPath has "Temporary ASP.NET Files" and FileName endswith ".dll")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

## Analyze

- A server script written by `w3wp.exe` into an upload path is high-confidence web shell deployment. Correlate timing with H1 (DNS beacon) and H2 (worker shells).
- The temp-DLL branch is the IR-critical one: compiled artifacts in `Temporary ASP.NET Files` are generated on first access of each shell and **outlive deletion of the source** — they are reactivation points and forensic evidence.

## Act

- Confirmed: collect both the source scripts and **every** compiled DLL in the ASP.NET temp directories; eradication is incomplete until the temp directories are cleared and the entry vector (EOL .NET app / exposure) is remediated. Closing on "web shell deleted" leaves the operator a path back.
