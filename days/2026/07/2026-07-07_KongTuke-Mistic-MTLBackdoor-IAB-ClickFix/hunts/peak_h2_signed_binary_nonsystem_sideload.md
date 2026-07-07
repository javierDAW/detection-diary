# PEAK Hunt H2 — Signed Binary Loading a System-Named DLL From a Non-System Path

**Hypothesis:** The signed Microsoft binary `MpExtMs.exe` was placed in a user-writable directory
alongside a malicious `version.dll` (API-hooking loader) and `EndpointDlp.dll` (Backdoor.Mistic),
so a trusted, signed process loads attacker code that masquerades as Microsoft endpoint-DLP tooling.

**Prediction / expected evidence:** `MpExtMs.exe` running from `%TEMP%`, `%APPDATA%`,
`%PROGRAMDATA%` or a user profile path (not the Defender platform directory), loading
`version.dll` / `EndpointDlp.dll` from that same non-System32 path.

## Data sources
- Defender XDR `DeviceImageLoadEvents`, `DeviceProcessEvents`.
- Sysmon EID 7 (image load) with signature status; EID 1 for the process path.

## Analytic (Defender XDR)
See `kql/mistic_sideload_endpointdlp_nonsystem.kql`. Generalise beyond the two filenames: hunt any
signed binary loading a "system-sounding" DLL (`version.dll`, `EndpointDlp.dll`) from a user-writable
directory. The tell is path + signer mismatch at load time, not a hash.

## Triage
- Compare `MpExtMs.exe` location to the genuine Defender platform path.
- Submit `version.dll` / `EndpointDlp.dll` for hash + IAT review (GetModuleFileNameW/LoadLibraryW hooks).
- Mistic is in-memory with a self-delete kill switch: capture a memory image before containment.

## Outcome
- [ ] Confirmed Mistic sideload  - [ ] Legit Defender update  - [ ] Inconclusive
