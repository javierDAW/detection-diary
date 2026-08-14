# PEAK Hunt H2 — Kernel-integrity tamper after the AFD.sys LPE

**Author:** Jarmi · **Date:** 2026-08-14 · **ATT&CK:** T1068 (Exploitation for PrivEsc), T1014 (Rootkit), T1562.006 (Indicator Blocking), T1055.001 (DLL Injection)

## Hypothesis
If CVE-2026-68820 was exploited on a host, then FudModule 3.1 will have degraded host telemetry (ETW providers / NT Kernel Logger dropping, EDR going silent) and tampered with Smart App Control, around a SYSTEM `msiexec.exe` with an anomalous parent into which MISTPEN was injected.

## Prepare
- Data sources: EDR sensor-health logs, ETW session inventory, Defender XDR `DeviceProcessEvents`/`DeviceEvents`, Sysmon EID 1/8/10.
- Scope: hosts flagged in H1, plus any Windows 11 (26100/26200) host unpatched for CVE-2026-68820.
- Baseline: normal parents of SYSTEM `msiexec.exe`; normal ETW provider set per host.

## Execute
1. SYSTEM `msiexec.exe` with a non-installer parent and no MSI on the command line (see `kql/system_msiexec_injection_target.kql`; Sigma `proc_system_msiexec_anomalous_parent.yml`).
2. EDR/ETW "went quiet" windows: sensor gaps on hosts that stayed otherwise active; NT Kernel Logger stop; a sudden drop in ETW provider count.
3. Smart App Control policy state flipping to unenforced (`VerifiedAndReputablePolicyState` reset); correlate with the msiexec anomaly.
4. Cross-process injection into `msiexec.exe` (Sysmon EID 8/10); FudModule sample hash `3b6378df...` from `iocs.csv`.

## Act
- Any confirmed integrity-tamper cluster: treat the host as SYSTEM-compromised — reimage, do not clean; patch CVE-2026-68820 before re-onboarding.
- Alert on ETW/EDR silence as a first-class signal (absence-of-telemetry detection), not just on positive events.

## Notes
Because FudModule is data-only (DKOM) and no driver is dropped, BYOVD/unsigned-driver detections will not fire — the tell is telemetry going dark, not a bad file.
