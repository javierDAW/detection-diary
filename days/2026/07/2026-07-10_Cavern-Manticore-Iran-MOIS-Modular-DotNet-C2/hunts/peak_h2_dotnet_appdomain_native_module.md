# PEAK Hunt H2 — anomalous .NET module loading (AppDomain isolation + Native-AOT n- DLLs)

**Hypothesis.** The Cavern Agent runs a dispatcher that loads native `n-` DLLs via `LoadLibraryA` and managed modules via per-module AppDomain isolation. In a compromised host we expect a mixed-mode process performing anomalous .NET AppDomain creation and loading DLLs whose names begin with `n-` (e.g. `n-HTCommp.dll`, `n-ten.dll`, `n-sws.dll`) outside any development context.

**Prepare.** Data sources: Sysmon EID 7 (Image Load) / `DeviceImageLoadEvents`, CLR/ETW `.NET` runtime provider telemetry if collected, and EID 1 for process lineage. Identify your legitimate .NET development and hosting hosts to baseline expected AppDomain activity.

**Execute.**
1. Surface image loads of DLLs matching `n-*.dll` (native-AOT modules) by non-developer processes; the side-load host from H1 loading these is high confidence.
2. Look for `clr.dll` / `coreclr.dll` loaded into an unexpected host together with repeated short-lived module DLL loads (per-module AppDomain load/unload).
3. Correlate module DLL loads with subsequent recon behaviour: LDAP queries, SMB/port scanning, SQL client activity, SOCKS5/WebSocket egress.
4. Check module hashes against the Cavern SHA256 set (`n-HTCommp`, `n-ten`, `n-sws`, `mhm`, `db`, `ode`).

**Act.** Because modules are unloaded after use, prioritise a live memory image over on-disk collection. Map which modules ran (recon vs credential vs tunnel) to scope the intrusion, then rotate exposed credentials.

**Notes.** The `n-` naming and the uniform `get_version` interface are durable structural tells that survive per-victim recompilation. Native-AOT DLLs have no IL metadata, so triage them as native binaries.
