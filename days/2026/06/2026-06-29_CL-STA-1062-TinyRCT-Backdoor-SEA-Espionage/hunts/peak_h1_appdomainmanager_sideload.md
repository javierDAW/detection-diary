# PEAK Hunt H1 — AppDomainManager sideload into a trusted launcher

**Hypothesis.** A CL-STA-1062 operator has placed a rogue `*AppDomainManager.dll` next to a
signed .NET launcher and a malicious `*.exe.config` in a user-writable directory, so attacker
code executes inside the trusted process (T1574.014). We expect a signed/legitimate binary
loading an AppDomainManager assembly from `Downloads`, `AppData`, `Temp`, `ProgramData`, or
`Users\Public`.

**ABLE breakdown.**
- **Actor:** CL-STA-1062 (overlaps UAT-7237).
- **Behavior:** CLR loads an attacker AppDomainManager assembly at process start.
- **Location:** Windows endpoints/servers exposed via vulnerable web apps; user-writable paths.
- **Evidence:** `DeviceImageLoadEvents` (Defender XDR), Sysmon EID 7 (ImageLoad).

**Data sources.** Defender XDR `DeviceImageLoadEvents`; Sysmon Event ID 7.

**Hunt logic (Defender XDR).**
```kql
DeviceImageLoadEvents
| where FileName endswith "AppDomainManager.dll"
| where FolderPath has_any (@"\Downloads\", @"\AppData\Local\", @"\AppData\Roaming\", @"\Temp\", @"\ProgramData\", @"\Users\Public\")
| where not(FolderPath has_any (@"\Program Files\", @"\Microsoft Visual Studio\"))
| summarize count(), make_set(InitiatingProcessFileName) by DeviceName, FolderPath
```

**Triage / pivots.**
1. Confirm a sibling `*.exe.config` referencing `appDomainManagerAssembly` / `appDomainManagerType`.
2. Check the loading process for outbound HTTP to staging IP `139.180.134[.]221`.
3. Pivot to a scheduled task named `GoogleUpdaterTaskSystem*` created near the load time.

**Expected benign.** Developer machines running .NET apps that ship a custom AppDomainManager
assembly from a profile path; allowlist by signer.

**Outcome.** Promote confirmed sideloads to the Sigma `image_load` rule; capture any new
launcher/DLL/config triplet names as variants.
