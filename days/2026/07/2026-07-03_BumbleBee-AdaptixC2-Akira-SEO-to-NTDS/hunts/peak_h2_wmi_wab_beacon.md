# PEAK Hunt H2 — WMI-spawned WAB.EXE masquerade beacon (AdaptixC2)

**Hypothesis (P).** On a beachhead host, `WmiPrvSE.exe` spawns a process whose PE `OriginalFileName` is `WAB.EXE` (Windows Address Book) from a user `%AppData%` path rather than Program Files, and that process then beacons over HTTP to a single low-reputation IP. This is the AdaptixC2 foothold (`AdgNsy.exe` = renamed `wab.exe` + shellcode, launched via WMI).

**Why it works.** WMI-based launch (`ParentImage=WmiPrvSE.exe`) is unusual for a GUI utility like `wab.exe`, and the `OriginalFileName`/path mismatch survives renaming and hashing. Adding the outbound beacon confirms it is a C2 channel, not a stray copy.

**Enrich (E).** Pull process creation with parent and PE metadata (Sysmon EID 1 / `DeviceProcessEvents`), then join to outbound network events on the same host and process.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where ProcessVersionInfoOriginalFileName =~ "WAB.EXE"
| where FolderPath !has @"\Program Files\Windows Mail\" and FolderPath !has @"\Program Files (x86)\Windows Mail\"
| project SpawnTime=Timestamp, DeviceName, FolderPath, FileName, ProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(14d) and RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceName, InitiatingProcessId, RemoteIP, RemoteUrl
  ) on DeviceName
| where NetTime between (SpawnTime .. (SpawnTime + 2h))
```

**Analyze (A).** A WMI-spawned `WAB.EXE` from AppData that talks to one external IP is almost certainly a masqueraded beacon. Distinct external IP count is usually one (single C2), which helps separate it from legitimate network chatter.

**Knowledge (K).** Baseline any management tooling that legitimately invokes `wab.exe` from Program Files. Promote to `sigma/adaptixc2_wab_masquerade_wmi_spawn.yml`; capture the beacon IP for the `suricata/` rules and for retro-hunting other hosts.
