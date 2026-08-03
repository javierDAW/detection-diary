# PEAK Hunt H2 - Service-Loader DLLs and NVIDIA/Realtek Side-Loading

- Author: Jarmi
- Date: 2026-08-03
- Frame: PEAK
- MITRE: T1543.003 (Windows Service), T1574.002 (DLL Side-Loading), T1620 (Reflective Code Loading)

## Hypothesis
The intrusion persists through a service whose DLL loads via ServiceMain=`RegisterService`
(OctLurk `oleasapi.dll`, LurkProxy `msbasesysdc.dll`) or through a legitimate signed host
binary side-loading a malicious DLL (SilkLurk: NVIDIA `NetSetSvc.exe`/`nvgwls.exe` loading
`nvml.dll`/`vulkan-1.dll`; Realtek `RtkSmbus.exe`/`RtkNGUI64.exe` loading `RtkSmbusLoc.dll`/
`RtkNGUI64Loc.dll`; PlugX: Symantec `RasTls.exe` loading `RasTls.dll`). The backdoor lives in
memory, so the on-disk tell is the loader DLL in an unusual path plus a service pointing to it.

## Data sources
- Defender XDR `DeviceImageLoadEvents` (signed EXE loading an unsigned DLL from a non-standard
  path), `DeviceRegistryEvents` (Services\*\Parameters ServiceDll / ServiceMain).
- Windows System 7045 (service installed); Sysmon EID 7 (image load), EID 13 (registry set).

## Execute
1. List services created in the incident window; flag ServiceDll paths outside System32 and any
   ServiceMain value equal to `RegisterService`; flag service names NgcCIntSvc/Cusrxsrv/RmSs.
2. For NVIDIA/Realtek/Symantec host binaries, list the DLLs they load and their sign status +
   path; flag `nvml.dll`, `vulkan-1.dll`, `RtkSmbusLoc.dll`, `RtkNGUI64Loc.dll`, `RasTls.dll`
   loaded from ProgramData / Network\Connections / html help.
3. Confirm the process has a private, executable, unbacked memory region (reflective payload).

## Act
- True positive: dump the injected region, extract config (C: drive serial or computer-name
  keyed), pivot to C2. False positive: legitimate vendor updaters side-load their own signed
  DLLs from Program Files - path and signature disambiguate.

## Notes
Linked Sigma: reg_octlurk_service_registerservice_loader.yml.
