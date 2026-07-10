# PEAK Hunt H1 — DLL side-load of a system-named DLL (uxtheme.dll)

**Hypothesis.** Cavern Manticore established a foothold by side-loading the Cavern Agent: a legitimate signed `WinDirStat.exe` loading a trojanized `uxtheme.dll` from a non-System32 path. Because `uxtheme.dll` legitimately resolves only from Windows system directories, any load from a temp/staging/user-writable path is a strong side-load signal.

**Prepare.** Data sources: Sysmon EID 7 (Image Load) or Defender `DeviceImageLoadEvents`, plus EID 1 / `DeviceProcessEvents`. Build (or reuse) an allowlist of applications that legitimately bundle their own `uxtheme.dll`.

**Execute.**
1. List image loads of `uxtheme.dll` whose folder is not under `System32`, `SysWOW64`, or `WinSxS`.
2. For each, record the loading process, its folder, and hash; flag any signed utility (especially `WinDirStat.exe`) loading it from `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\` or `\Downloads\`.
3. Confirm a co-located `uxtheme.dll` next to the host binary (the side-load pattern).
4. Pivot on the loading process's parent — a SysAid update process or RMM agent as parent raises confidence.

**Act.** Capture memory of the hosting process before terminating it (modules live in-process). Collect the side-load pair, hash the DLL against the Cavern SHA256 set, and pivot to H2 (module loading) and H3 (C2/relay).

**Notes.** The tell is hash-independent and portable across the whole side-load class — the same shape as `version.dll` in the KongTuke/Mistic case. Baseline first; some legitimate portable apps ship their own `uxtheme.dll`.
