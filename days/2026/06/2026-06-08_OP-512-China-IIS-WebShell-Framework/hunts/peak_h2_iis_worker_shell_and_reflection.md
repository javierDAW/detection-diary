# PEAK Hunt H2 — IIS worker spawning shells + reflective .NET loads

**Hypothesis.** If an operator is driving commands through OP-512's `.ashx` handlers and escalating privileges, then `w3wp.exe` will spawn command interpreters / LOLBins and/or reflectively load .NET assemblies into its own memory (the Potato-suite + "GhostKit" in-memory tooling).

**ATT&CK.** T1505.003 (Web Shell), T1059.003 (Windows Command Shell), T1620 (Reflective Code Loading), T1134.001 (Token Impersonation), T1068 (Exploitation for Priv-Esc), T1033 (System Owner/User Discovery).

## Prepare

- Telemetry: Sysmon EID 1 (process creation), Defender `DeviceProcessEvents`; for reflective loads, EDR .NET-runtime telemetry / `DeviceImageLoadEvents` and `DeviceEvents`.
- Scope: web/DMZ-server watchlist. Baseline benign `w3wp.exe` children (build agents, admin tooling).

## Execute

```kql
// Worker spawning shells / LOLBins
DeviceProcessEvents
| where Timestamp > ago(45d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","cscript.exe","wscript.exe","rundll32.exe","net.exe","net1.exe")
| extend Base64Whoami = ProcessCommandLine has_any ("-enc","FromBase64String") and ProcessCommandLine has "whoami"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Base64Whoami
| order by Timestamp desc
```

## Analyze

- `w3wp.exe` → `whoami` / `whoami /priv` (especially base64-encoded) is a strong tell; OP-512's encoded `whoami` matched a Flax Typhoon playbook char-for-char.
- Reflective module loads from temp / ASP.NET-temp paths into the worker indicate the memory-only Potato suite. Note that prevention killing the process may be followed by an immediate IIS restart and reload — look for the **detect-kill-reload loop** across successive `w3wp.exe` PIDs.

## Act

- Confirmed: isolate host + terminate sessions (process kill alone loops on IIS restart), capture memory before reboot, scope account context (the discovery ran under a limited service account, so escalation may be in progress).
