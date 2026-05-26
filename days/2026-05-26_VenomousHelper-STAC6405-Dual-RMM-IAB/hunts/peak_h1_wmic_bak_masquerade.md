# PEAK H1 — Renamed WMIC LOLBin (wmic.exe.bak) hunt

## Hypothesis

If a signed-RMM-as-IAB operator from the VENOMOUS#HELPER / STAC6405 cluster (Securonix 2026-05-04) is present on a host, then a copy of WMIC named `wmic.exe.bak` exists under `C:\Windows\System32\wbem\` and is invoked via `cmd.exe /c` at a 67-second cadence to enumerate the `root\SecurityCenter2` WMI namespace, regardless of whether canonical `wmic.exe` is also being invoked in parallel.

## Why this discriminates

Legitimate administrators almost never rename WMIC. The rename pattern is operator-specific: the suffix `.bak` is the cheapest way to defeat name-based EDR detections that key on the exact image name `wmic.exe`. Securonix explicitly labels the presence of `wmic.exe.bak` as the single highest-confidence static host indicator of this cluster. The discriminator is therefore both static (the file on disk) and dynamic (invocation by `cmd.exe /c` with a `wmic.exe.bak` argument).

## Expected benign

- Some endpoint backup or imaging tooling enumerates system binaries and writes a `.bak` copy alongside the original — these almost always land under the tool's working directory, not under `C:\Windows\System32\wbem\`.
- An administrator using `robocopy /SAVE` or `xcopy` with a hand-typed backup-suffix could legitimately produce a `.bak` copy of a system binary; this is rare, traceable to a change ticket, and the file should be removed once the test concludes.

## Expected malicious

- `C:\Windows\System32\wbem\wmic.exe.bak` exists with SHA256 matching the canonical `wmic.exe` of the same Windows build (it is a verbatim copy, not a different binary).
- Process creation events show `cmd.exe /c "wmic.exe.bak /namespace:\\root\SecurityCenter2 ..."` firing in 67-second cadences with no human at the keyboard.
- Each batch fires four queries (`AntiVirusProduct`, `AntiSpywareProduct`, `FirewallProduct`, plus `netsh advfirewall show all State`) with equal counts in any reasonable window — the textbook signature of a single batched timer.

## Actions

1. Hunt the file with a single Defender XDR `DeviceFileEvents` query (see `kql/01_defender_wmic_bak_masquerade.kql`) across all hosts in the fleet, 30-day window.
2. For every host returned, pull the parent chain of the `wmic.exe.bak` process — most should resolve to `cmd.exe` under `C:\ProgramData\JWrapper-Remote Access\...`.
3. Confirm by querying `DeviceFileEvents` for any other `*.exe.bak` under `C:\Windows\System32\` and `C:\Windows\System32\wbem\` — this is a generalizable hunt that catches operator-led name rotation (`wmic.exe.copy`, `wmic.exe.old`, etc.).
4. Preserve any matching `wmic.exe.bak` for forensic capture before deletion — it is the cleanest fleet-wide cluster anchor.

## Telemetry

- Defender XDR: `DeviceFileEvents`, `DeviceProcessEvents`.
- Sysmon: EID 1 (process creation), EID 11 (file create).
- Velociraptor: `Windows.Forensics.FilenameSearch` with pattern `wmic.exe.bak`.
