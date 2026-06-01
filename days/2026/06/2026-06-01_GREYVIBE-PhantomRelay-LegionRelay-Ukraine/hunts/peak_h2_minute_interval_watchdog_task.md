# PEAK Hunt H2 — minute-interval scheduled tasks re-launching PowerShell

**Hypothesis:** A PhantomRelay watchdog has installed a scheduled task that
re-runs a user-path PowerShell script every 1-3 minutes to keep the RAT alive.

## Prepare

The PhantomRelay watchdog creates a scheduled task that fires one minute after
creation and every three minutes thereafter; if no active C2 session exists it
re-executes the dropped initial-stage script. Scripts live under `%PROGRAMDATA%`
(V1) or `%LOCALAPPDATA%` (V2). Legitimate tasks rarely re-run a user-writable
PowerShell script on a sub-five-minute cadence, so the recurrence plus a
scripting-host action is the anchor.

- Data sources: `DeviceProcessEvents` (schtasks.exe) + Security 4698 (task
  created) + Microsoft-Windows-TaskScheduler/Operational.
- Scope: all Windows endpoints, 30-day look-back.

## Execute

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where ProcessCommandLine has "minute" and ProcessCommandLine has_any ("/mo 1","/mo 2","/mo 3")
| where ProcessCommandLine has_any ("powershell","pwsh",".ps1")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

Cross-check survivors against task actions that point into `%PROGRAMDATA%`,
`%LOCALAPPDATA%` or `%TEMP%`, and against the presence of `razer_update.log`.

## Act

- **Expected benign:** monitoring/telemetry agents and a few software updaters
  legitimately poll every 1-3 minutes. Baseline by task name, author, and the
  exact action path; allowlist confirmed-good entries.
- **Suspicious:** task action runs a `.ps1` from a user-writable directory, has a
  random or product-spoofing name, and was created by a non-admin interactive
  session.
- **Pivot:** dump the task action script, hash it, and retro-hunt the script body
  with `yara/greyvibe_powershell_implants.yar`; check the same host for H1 and H3.

Linked detections: `sigma/02_greyvibe_watchdog_schtask_3min.yml`,
`kql/k2_greyvibe_watchdog_schtask.kql`.
