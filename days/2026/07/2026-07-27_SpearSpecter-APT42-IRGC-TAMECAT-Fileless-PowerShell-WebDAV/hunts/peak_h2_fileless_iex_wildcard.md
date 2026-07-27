# PEAK Hunt H2 — fileless wildcard Invoke-Expression (TAMECAT loader)

**Prepare**

- Hypothesis: If TAMECAT is resident, PowerShell Script Block Logs contain a payload read (`Get-Content` or `invoke-restmethod`) fed into a wildcard-resolved `Invoke-Expression` such as `&(gcm i*x)` / `.(gcm i*ee*)`, executed in memory.
- Scope: all Windows endpoints with PowerShell Script Block Logging (EID 4104) enabled.
- Data: `Microsoft-Windows-PowerShell/Operational` 4104/4103; Defender `DeviceEvents` (PowerShell). 
- ATT&CK: T1059.001, T1027, T1140, T1620.

**Execute**

1. Query EID 4104 for `gcm i*x`, `gcm i*ee*`, `(gcm i*` combined with `Get-Content` or `invoke-restmethod`.
2. Look for `-UserAgent 'Chrome'` on `invoke-restmethod` to `*.workers.dev` and for `[Scriptblock]::Create` immediately preceding an `&`/`.` invocation.
3. Pivot on payload paths: `%LOCALAPPDATA%\Microsoft\Windows\AutoUpdate\*.txt` referenced by a `Get-Content` (name is random per host — match the directory, not the filename).
4. Check the parent chain: PowerShell launched with `-w 1` by `cmd.exe`/`conhost.exe`/`explorer.exe`.

**Act**

- True positive: capture the referenced `.txt`, decode module config (AES key `g9944pf33sbuuuspi3z2er6rqh9ermxk`, `Sec-Host` IV), enumerate persistence, isolate.
- Tuning: `gcm`/`Get-Command` wildcard resolution to `iex` is near-zero in benign automation; investigate all hits.

**Knowledge**

- If script-block logging is off on a subset of hosts, log a coverage gap. Feed newly seen module URLs to `iocs.csv`.
