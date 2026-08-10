# PEAK Hunt H2 - CornFlake persistence masquerade (Cloud Sync Service / svchost32)

## Hypothesis
CornFlake achieves persistence by copying itself to %APPDATA%\svchost32\svchost32.exe and
registering a Windows service named svchost32 with the display name "Cloud Sync Service" and a
watchdog that restores persistence when removed. If a host is implanted, we expect a process or
service whose name imitates svchost but runs from a user-writable path or carries that exact
display-name/description pair.

## Rationale (ABLE)
- **Actor behaviour:** redundant persistence (service + Run key + scheduled task) plus a
  self-healing watchdog; name masquerade against the legitimate svchost.exe.
- **Analytic value:** the "Cloud Sync Service" / "Synchronizes files with the cloud storage
  provider" pair is a specific, low-false-positive artifact; the AppData image path is anomalous
  for anything named svchost.

## Data sources
- Defender XDR: `DeviceProcessEvents`, `DeviceRegistryEvents`; Sysmon EID 1 (process create),
  EID 13 (registry set), EID 12/7.

## Query logic
1. `DeviceProcessEvents` where `FolderPath` ends with `\svchost32\svchost32.exe`, or `FileName`
   is svchost.exe but `FolderPath` contains `\AppData\`.
2. `DeviceRegistryEvents` where `RegistryKey` has `\Services\svchost32` and the DisplayName is
   "Cloud Sync Service" or the Description is "Synchronizes files with the cloud storage provider".
3. Union the two signals per device.

## Triage / expected vs benign
- **Malicious:** any svchost image outside System32/SysWOW64; the exact fake service metadata.
- **Benign:** none expected for the exact string pair; validate signer for any svchost32.exe.

## Pivots on a hit
- Dump the `sync.dat` config, pull the ECDH/JSON C2 endpoints, and enumerate the localhost HTTP
  API (/upload, /reload, /status) that companion payloads (ChocoShell) use.
