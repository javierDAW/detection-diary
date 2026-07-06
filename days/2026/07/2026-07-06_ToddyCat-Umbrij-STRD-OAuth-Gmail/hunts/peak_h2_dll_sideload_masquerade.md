# PEAK Hunt H2 - Signed loader sideloads Umbrij from a staging directory + masquerading task

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1574.001 DLL Search Order Hijacking; T1053.005 Scheduled Task; T1036.005 Masquerading: Match Legitimate Name or Location.

## Hypothesis
ToddyCat has staged one of its known signed loaders (GoogleDesktop.exe, BDSubWiz.exe / BDS.exe,
VSTestVideoRecorder.exe) in `\Users\Public`, `\Windows\Temp` or `\Windows\Vss` and used it to
DLL-sideload the Umbrij tool (GoogleServices.DLL / log.dll / the VS QualityTools VideoRecorderEngine
DLL). Persistence is a scheduled task named `KasperskyEndpointSecurityEDRAvp`, which Kaspersky itself
never creates.

## Prepare - data sources
- Defender XDR `DeviceImageLoadEvents` (sideloaded DLL name + load path), `DeviceProcessEvents`.
- Sysmon EID 7 (image load) and EID 1 (process creation); EID 11 for the DLL written to the staging dir.
- Scheduled-task inventory: `%WINDIR%\System32\Tasks`, `DeviceEvents` ActionType `ScheduledTaskCreated`,
  and the `TaskCache\Tree` registry hive.

## Execute - logic
1. Hunt the three loaders running from a staging directory that load one of the three known DLL names -
   see `kql/umbrij_dll_sideload.kql` and `sigma/umbrij_dll_sideload_signed_loader.yml`.
2. Enumerate scheduled tasks named `KasperskyEndpointSecurityEDRAvp` -
   `kql/umbrij_masquerading_task.kql` and `sigma/umbrij_masquerading_scheduled_task.yml`.
3. For each hit, validate the co-located DLL signature: the loader is signed, the sideloaded DLL is
   not (or is signed by an unexpected publisher).
4. Pivot to the launched child browser (H1) and the OAuth grant (H3) to confirm the full chain.

## Act - triage
- **Confirmed:** a signed loader in a staging path loading an unsigned `log.dll` / `GoogleServices.DLL`,
  and/or a `KasperskyEndpointSecurityEDRAvp` task on a host without that as legitimate persistence.
- **Escalation:** the same host then launches a headless browser with a debug port (H1).
- **Benign:** a genuine installer briefly executing one of these tools from `%TEMP%`; confirm the DLL
  publisher and path.

## Knowledge - notes
DLL sideloading is ToddyCat's signature - the loader is trusted by *name and signature*, so name-based
allowlisting fails; the anomaly is the *location* and the *co-located unsigned DLL*. Treat trusted-vendor
process names (Kaspersky, Bitdefender, Google, Visual Studio) as attacker cover, not as an exclusion.
