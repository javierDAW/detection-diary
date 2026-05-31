# PEAK H3 — SafeBoot-Network RMM persistence hunt

## Hypothesis

If an operator has planted a Safe Mode persistence anchor for an RMM-themed Windows service on a host, then a subkey appears under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\` whose name contains tokens like `Remote Access Service`, `RemoteSupport`, `JWrapper`, `SimpleHelp`, `SimpleGateway` or `ScreenConnect Client`, regardless of whether a legitimate IT-support team has authorised any RMM deployment.

## Why this discriminates

Most Windows services do not require a SafeBoot-Network entry — the SafeBoot keys are explicitly reserved for drivers and services that must run during Safe Mode boot. Legitimate RMM products almost never need to operate in Safe Mode with Networking. The combination of a SafeBoot-Network subkey AND an RMM-themed service name is therefore a strong indicator that the operator is intentionally arranging for the service to survive a Safe Mode cleanup — exactly the persistence primitive (T1562.009 Impair Defenses: Safe Mode Boot) Securonix documented in the VENOMOUS#HELPER case, and identical mechanically to the SafeBoot anchor Embargo used to disable EDR (covered in repo Day 22).

## Expected benign

- Storage drivers (e.g. `volsnap`, `iastorAVC`), network drivers (e.g. `tcpip`, `NetBT`) legitimately ship a SafeBoot-Network entry — none of these names contain RMM tokens.
- Some enterprise antivirus engines (legitimate vendors) register SafeBoot-Network entries for their core protection driver — vendor names should be allow-listed by image-signing certificate, and the subkey name itself usually carries the vendor name (e.g. `WdFilter`), not RMM concepts.

## Expected malicious

- A subkey under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\` named `Remote Access Service` (the VENOMOUS#HELPER name) or any rotation that combines RMM concepts: `RemoteSupport`, `ServiceHelp`, `SimpleHelp`, `SimpleGateway`, `JWrapper`, `ScreenConnect Client*`.
- The corresponding Windows service definition under `HKLM\SYSTEM\CurrentControlSet\Services\<same-name>\` points to an image path under `C:\ProgramData\` (not under `C:\Program Files` or `C:\Windows\System32\`).
- The image path resolves to a JWrapper bundle layout: `*\JWrapper-Remote Access\JWAppsSharedConfig\*` is the cleanest sub-anchor.

## Actions

1. Sweep every host with the registry hunt: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network" /s` and capture every subkey name returned.
2. Reduce to subkey names that match any of the RMM tokens listed in `Expected malicious`.
3. For every match, pull the corresponding service definition from `HKLM\SYSTEM\CurrentControlSet\Services\<name>\` and the `ImagePath` value. Any image under `C:\ProgramData\` is a strong follow-up signal.
4. For every match, confirm the canonical IOCs from PEAK H1 (`wmic.exe.bak`) and PEAK H2 (three polling cadences) on the same host. A match on all three hypotheses on the same host is unambiguous.

## Telemetry

- Defender XDR: `DeviceRegistryEvents` for `RegistryKey` and `RegistryValueName` matching the SafeBoot path and RMM tokens.
- Sysmon: EID 12 / EID 13 (registry key create / value set).
- Velociraptor: `Windows.Registry.NTUser` and custom artifact for SafeBoot-Network subkey enumeration.
- KAPE: `RegistryHives` collection target for `SYSTEM` hive offline review.
