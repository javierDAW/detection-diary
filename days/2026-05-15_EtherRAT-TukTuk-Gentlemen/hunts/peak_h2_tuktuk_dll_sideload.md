# PEAK H2 — Signed userland binary side-loading from non-install paths

## Hypothesis

A signed userland binary from the TukTuk targeting list (`Greenshot.exe`, `SyncTrayzor.exe`, `docfx.exe`, `Cake.exe`) running outside its official install path (i.e. not from `C:\Program Files` or `C:\Program Files (x86)`) and loading a helper DLL such as `log4net.dll`, `Newtonsoft.Json.dll`, or `System.Net.Http.dll` from the same directory is side-loading TukTuk, an AI-generated framework observed by The DFIR Report TB40048 in May 2026.

## Why this discriminates

DLL search-order hijacking under signed binaries gives the attacker free defence evasion because the parent process is signed and trusted. The signal that this is malicious and not just a portable install is the helper DLL being unsigned, signed by a different chain than the host, or simply not present in the official vendor distribution.

## Query — KQL (Defender XDR)

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("Greenshot.exe", "SyncTrayzor.exe",
                                        "docfx.exe", "Cake.exe")
| where FileName in~ ("log4net.dll", "Newtonsoft.Json.dll", "System.Net.Http.dll")
| where not(FolderPath startswith @"C:\Program Files\")
   and not(FolderPath startswith @"C:\Program Files (x86)\")
   and not(FolderPath startswith @"C:\Windows\Microsoft.NET\")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          FileName, FolderPath, SHA256
```

## Expected benign

- Portable installs of these tools under the user profile may ship their own dependency DLLs. Verify the Authenticode chain on the helper DLL with `signtool verify /v <dll>`.
- Internal developer toolchains that ship Greenshot or Cake from a build artefact share may surface here; whitelist the known internal share path.

## Expected malicious

- Helper DLL loaded from `\Users\<user>\AppData\` or `C:\temp\`, no Authenticode signature or signed by an unfamiliar issuer.
- Helper DLL hash matches the known TukTuk anchor `19021e53b9929fdf4b7d0e0707434d56bb73c1a9b7403c8837b44d1c417198dc`.

## Action on match

1. Memory-dump the parent process and extract the loaded .NET module with `dnSpyEx` or `dotPeek`. Publish the SHA256.
2. Network-isolate the host. Audit GoTo Resolve service installs on neighbouring hosts.
3. Submit the suspicious DLL to your malware analysis pipeline; correlate with the YARA rules in this folder (`yara/tuktuk_sideload_log4net_2026.yar`).
