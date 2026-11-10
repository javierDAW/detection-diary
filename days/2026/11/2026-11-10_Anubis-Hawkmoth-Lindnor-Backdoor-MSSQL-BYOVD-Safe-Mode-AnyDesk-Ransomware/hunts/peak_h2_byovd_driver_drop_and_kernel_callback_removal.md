# PEAK hunt H2 - BYOVD driver drops, kernel callback removal and EDR tamper before Anubis

## Prepare

- **Hypothesis:** an operator dropped publicly known, signed vulnerable drivers and EDR-killer tools onto a compromised server, loaded a driver and used it to enumerate and remove kernel callbacks (blinding the EDR) shortly before deploying the Anubis payload.
- **Why:** Symantec (Broadcom, 2026-11-05) reports that within about an hour at least 13 executables and five vulnerable drivers were dropped: `havoc.sys`, `monprocessex.sys`, `xhunter1.sys`, `bdapiutil64.sys`, `fly.sys`. `gbbsym.exe` and `symgooq.exe` masquerade as Symantec; `-l` lists kernel callbacks through a loaded vulnerable driver and `-d` lists and removes them (observed command lines used `-d`). `huntreagent.exe` and `s1.exe` (same size, different hashes) were not blocked. Other dropped names: `bdr.exe`, `hwaudioch.exe`, `gibformin.exe`, `test.exe`, `xs.scr`, `gibfor.exe`, `g.exe`, `backup.exe`, `rustr.exe`. The payload `iservice.exe` was blocked and nothing was encrypted.
- **Honesty:** derived from the Symantec report as relayed by GBHackers and Cyber Security News (2026-11-09); no first-hand sample analysis. The report does not label which tools beyond `gbbsym.exe` / `symgooq.exe` are EDR killers, nor the drop paths or service names used to load the drivers. Short names such as `test.exe`, `g.exe`, `backup.exe`, `s1.exe` are only useful with hashes.
- **Scope:** 90 days of Defender XDR process, file, driver-load and service telemetry; servers first (SQL Server hosts), then the rest of the estate.
- **Confidence:** high for hash matches; medium for driver-name matches outside the driver store; medium for the callback-removal behaviour.

## Execute

**Data sources / content:** `sigma/02_anubis_lindnor_edr_killer_and_payload_process.yml`, `sigma/03_anubis_byovd_driver_drop_and_ransom_note.yml`, `kql/k2_mde_lindnor_anubis_byovd_hashes_and_names.kql`.

1. Run k2 and triage rows with `CallbackRemoval = true` first (a `-d` run means the host's EDR may be blind and its own telemetry may be incomplete after that time).
2. Hunt for kernel-driver services created from non-standard paths (generic BYOVD behaviour, not a published IOC):

```powershell
# Author: Jarmi
Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.PathName -notmatch '\\Windows\\System32\\(drivers|DriverStore)\\' } |
  Select-Object Name, State, StartMode, PathName
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 500 |
  Where-Object { $_.Message -match 'kernel mode driver' } |
  Select-Object TimeCreated, @{n='Msg';e={$_.Message}}
Get-ChildItem -Path C:\ProgramData, C:\Users, C:\Windows\Temp -Recurse -Force -Include havoc.sys,monprocessex.sys,xhunter1.sys,bdapiutil64.sys,fly.sys -ErrorAction SilentlyContinue |
  Get-FileHash -Algorithm SHA256
```

3. Check the Microsoft vulnerable driver blocklist status (`HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable`) and HVCI on every hit; compare the five driver hashes against the blocklist and LOLDrivers.
4. Look for EDR / AV health gaps on the same hosts: sensor heartbeat loss, service stop, tamper-protection alerts, sudden drop in event volume right after a driver load.
5. Correlate with H1 (SafeBoot AnyDesk) and with any `restore files.txt` / `restore files.html` note or `.anubis` rename (Sigma 03).

## Act

- **Expected benign:** vendor or research labs staging vulnerable drivers; unrelated drivers that share a short name (`fly.sys`, `havoc.sys`) - verify hash and signer; in-house tools named `bdr.exe` or `backup.exe`.
- **Action on match:** a driver from the list loaded outside the driver store, or `gbbsym.exe` / `symgooq.exe` executed = active hands-on-keyboard intrusion. Isolate from the network (not just via the possibly blinded EDR - use switch / firewall), acquire memory before reboot, collect the driver files, the Amcache / Shimcache entries and System 7045 events.
- **Escalation:** declare a ransomware incident; check backups and hypervisors for the same toolset; hunt the whole estate by hash with k2; pivot to H3 for the Lindnor foothold.
- **Detections:** promote Sigma 02 / 03; enable the Microsoft vulnerable driver blocklist and HVCI; add the five driver hashes to WDAC deny policies.
- **Exit criteria:** every listed hash and driver name accounted for; blocklist enforced on servers; EDR telemetry continuity verified on all hit hosts.
- **Caveat:** BYOVD toolkits rotate drivers and rename files; the durable signal is a signed but vulnerable driver loaded from a user-writable path followed by EDR silence.
