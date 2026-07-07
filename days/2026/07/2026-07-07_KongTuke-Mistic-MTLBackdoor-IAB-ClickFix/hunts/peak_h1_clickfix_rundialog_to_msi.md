# PEAK Hunt H1 — ClickFix Run-Dialog to Remote MSI

**Hypothesis:** A Woodgnat/KongTuke lure (fake CAPTCHA, fake browser crash, or fake IT-support
Teams chat) tricked a user into pasting a one-line command into the Run dialog or Explorer
address bar, spawning an interactive `powershell.exe`/`curl.exe`/`certutil.exe` child of
`explorer.exe` that pulled a remote `.msi` (e.g. `hxxp://thomphon.com/update.msi`).

**Prediction / expected evidence:** `explorer.exe` -> shell/download tool with an `http(s)` URL and
`.msi` in the command line, followed within seconds by `msiexec.exe` executing the downloaded file,
and RunMRU registry writes matching the pasted command.

## Data sources
- Defender XDR `DeviceProcessEvents` (parent = explorer.exe), `DeviceNetworkEvents`.
- Sysmon EID 1 (process create), EID 3 (network), EID 13 (RunMRU registry set).
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`.

## Analytic (Defender XDR)
See `kql/clickfix_rundialog_powershell_msi.kql`. Pivot on `AccountName` + `DeviceName`, then join
to `DeviceNetworkEvents` for the MSI host and to `DeviceFileEvents` for the dropped MSI hash.

## Triage
- Confirm the MSI host against `iocs.csv` / `feeds/blocklists`.
- Pull RunMRU to recover the verbatim pasted command (strong ClickFix confirmation).
- Escalate if `msiexec` then spawns/loads `MpExtMs.exe` + `version.dll` (pivot to H2).

## Outcome
- [ ] Confirmed ClickFix delivery  - [ ] Benign admin MSI  - [ ] Inconclusive
