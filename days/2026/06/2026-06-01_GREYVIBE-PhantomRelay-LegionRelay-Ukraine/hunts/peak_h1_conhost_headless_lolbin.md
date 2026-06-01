# PEAK Hunt H1 — conhost.exe --headless launching scripting hosts

**Hypothesis:** An operator using GREYVIBE tradecraft is hiding PowerShell
execution behind `conhost.exe --headless` on at least one host in the estate.

## Prepare

GREYVIBE used `conhost.exe --headless` to launch PowerShell across PhantomMail,
PhantomClick, PrincessClub, PhantomRelay and LegionRelay, and to relaunch the
`starter.ps1` privilege-escalation helper from hijacked shortcuts. `conhost
--headless` runs a console app with no visible window and is rare in benign
fleets outside Windows Terminal internals, which makes it a strong long-tail
anchor that survives the actor's frequent obfuscator and hash rotation.

- Data sources: `DeviceProcessEvents` (Defender XDR) / Sysmon EID 1.
- Scope: all Windows endpoints, 30-day look-back.

## Execute

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "conhost.exe" and ProcessCommandLine has "--headless"
| where ProcessCommandLine has_any ("powershell", "pwsh", "cmd")
| summarize Hosts=dcount(DeviceName), Cmds=make_set(ProcessCommandLine, 20),
            Parents=make_set(InitiatingProcessParentFileName, 20) by InitiatingProcessFileName
| order by Hosts asc
```

Stack-rank by rarity: the least-common parent/command-line tuples are the most
suspicious. Pivot any hit to the spawning process tree and to outbound network.

## Act

- **Expected benign:** Windows Terminal (`OpenConsole.exe` / `WindowsTerminal.exe`)
  and some IDE/test harnesses invoke `conhost --headless`. Baseline and exclude.
- **Suspicious:** `--headless` spawned by `wscript.exe`, `mshta.exe`, an archive
  tool, an Office app, or a PowerShell one-liner that also fetches remote script.
- **Pivot:** if confirmed, hunt the same host for H2 (watchdog task) and H3
  (download cradle), and sweep for the artifact file names in Sigma rule 03.

Linked detections: `sigma/01_greyvibe_conhost_headless_powershell.yml`,
`kql/k1_greyvibe_conhost_headless.kql`.
