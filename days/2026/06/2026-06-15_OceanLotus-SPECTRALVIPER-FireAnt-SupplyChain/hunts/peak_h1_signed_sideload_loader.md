# PEAK Hunt H1 — Renamed signed binary side-loading a loader DLL

**Author:** Jarmi
**Date:** 2026-06-15
**Case:** OceanLotus (APT32) SPECTRALVIPER — FireAnt supply chain + construction-firm intrusion (ESET)
**Type:** Hypothesis-driven (PEAK)

## Hypothesis

OceanLotus executes SPECTRALVIPER through **DLL side-loading**: a legitimately-signed binary is renamed (`IntelAudioService.exe` = `dtlupdate.exe`; `Genuine.exe`/`Updater.exe`/`AutoCAD242.exe` = `Toolbox.exe`) and placed in a user-writable directory alongside an unsigned loader DLL (`DtlCrashCatch.dll` / `SetupUi.dll`). If this occurred in our estate, a signed executable ran from a non-standard path and loaded a non-Microsoft DLL from the same directory.

## ABLE framing

- **Actor:** OceanLotus / APT32 (Vietnam-aligned cyber-espionage).
- **Behaviour:** DLL side-loading (T1574.002) + masquerading via renamed signed hosts (T1036).
- **Location:** user-writable directories (AppData, user profile, ProgramData, Temp, Public); process-create and image-load telemetry.
- **Evidence:** `DeviceProcessEvents` (distinctive command lines), `DeviceImageLoadEvents` (loader DLL + signer of the loading process), Sysmon EID 1/7.

## Data sources

- Defender XDR `DeviceProcessEvents`, `DeviceImageLoadEvents`.
- Sysmon EID 1 (process creation), EID 7 (image load with signature info).
- Authenticode signer telemetry on the loading process and the loaded DLL.

## Query seed

See [../kql/oceanlotus_sideload_process.kql](../kql/oceanlotus_sideload_process.kql), [../kql/oceanlotus_dll_sideload.kql](../kql/oceanlotus_dll_sideload.kql) and [../sigma/spectralviper_signed_binary_sideload_launch.yml](../sigma/spectralviper_signed_binary_sideload_launch.yml).

```kql
DeviceImageLoadEvents
| where Timestamp > ago(45d)
| where FolderPath has_any (@"\Users\", @"\AppData\", @"\ProgramData\", @"\Temp\", @"\Public\")
| where InitiatingProcessFileName endswith ".exe"
| summarize dlls=make_set(FileName,50) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
```

## Triage / pivots

1. For each signed host in a user-writable path, list DLLs loaded from the same directory and check their signatures — an unsigned/non-Microsoft DLL beside a signed renamed binary is the side-loading tell.
2. Confirm the renamed host (compare original filename in PE version info vs on-disk name): `dtlupdate.exe`→`IntelAudioService.exe`, `Toolbox.exe`→`Genuine.exe`/`Updater.exe`/`AutoCAD242.exe`.
3. Pivot the loader DLL hash and pull child behaviour: injection into `OneDrive.Sync.Service.exe` (see H2) and outbound C2.
4. Hash the host + DLL and sweep the estate for the same pairing.

## Outcome / ABLE close

- **Found:** isolate the host, capture host+DLL+injected memory, escalate to the IR playbook.
- **Not found:** record side-loading coverage; convert the seed to a scheduled analytic for signed binaries loading unsigned DLLs from user paths.
