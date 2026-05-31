# PEAK H3 — ValleyRAT / Winos 4.0 plugin followed by a Python implant install

## Hypothesis

A host in the past fourteen days loaded a Windows-style DLL with a Chinese-named
file (`登录模块.dll_bin`, `上线模块.dll`, `保86.dll`, `winos4.0测试插件.pdb`) or
established a TCP session against 207.56.138.0/24 on port 6666, and shortly
afterwards a Python implant directory was created at `%LOCALAPPDATA%\appclient\`
or `C:\ProgramData\Tailscale\` with a Cython-compiled `appclient.core.*.pyd`
inside.

## Why this discriminates

The ValleyRAT / Winos 4.0 plugin chain is the unique mid-stage in Silver Fox
intrusions that ends in the new ABCDoor implant. Catching the Winos 4.0
component independently is valuable on its own — catching the chain plus the
Python implant install is a clean attribution call for Silver Fox in 2026.

## Expected benign vs malicious

DLLs containing CJK characters in filenames are exceedingly rare on enterprise
endpoints outside CN-localised builds. The combination "Chinese-named DLL load
or 207.56.138.0/24 egress AND Cython-compiled appclient.core .pyd writes inside
six hours" has no legitimate corollary that we have observed.

## Data sources

- Defender XDR `DeviceImageLoadEvents`.
- Defender XDR `DeviceNetworkEvents`.
- Defender XDR `DeviceFileEvents`.

## KQL — chained query

```kql
let plugin_loads = DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where FileName has_any ("登录模块","上线模块","保86","winos4")
   or FileName has_any (".dll_bin")
| project PluginTime=Timestamp, DeviceId, DeviceName, FileName, FolderPath;
let c2_hits = DeviceNetworkEvents
| where Timestamp > ago(14d)
| where (RemoteIP startswith "207.56.138." and RemotePort == 6666)
   or RemoteIP startswith "154.82.81."
| project C2Time=Timestamp, DeviceId, RemoteIP, RemotePort;
let py_drops = DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed")
| where (FolderPath has "\\AppData\\Local\\appclient\\" or FolderPath has "\\ProgramData\\Tailscale\\")
| where FileName endswith ".pyd" or FileName endswith ".py"
| project PyTime=Timestamp, DeviceId, FolderPath, FileName;
plugin_loads
| join kind=inner (py_drops) on DeviceId
| where PyTime between (PluginTime .. (PluginTime + 6h))
| union (
    c2_hits
    | join kind=inner (py_drops) on DeviceId
    | where PyTime between (C2Time .. (C2Time + 6h))
)
| project DeviceName, PluginTime, C2Time, PyTime, FolderPath, FileName
```

## Action on match

1. Treat as confirmed Silver Fox intrusion. The full kill chain is present.
2. Isolate, capture RAM, image the host.
3. Pull the AppData and ProgramData Tailscale directories — preserve the
   `appclient.core.cp310-win_amd64.pyd` for RE.
4. Pivot in M365 message-trace to the original tax-themed email — recipient set
   inventory determines blast radius.
5. Open a CTI ticket — this is China-nexus (medium-high confidence). If the
   victim is in industrial, consulting, retail or transport sectors, raise to
   the threat-hunting board for adjacent-tenant hunts.
