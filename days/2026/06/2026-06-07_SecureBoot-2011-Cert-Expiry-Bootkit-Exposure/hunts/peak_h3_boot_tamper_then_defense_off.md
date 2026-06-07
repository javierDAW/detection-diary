# PEAK Hunt H3 — boot-config tampering followed by HVCI / BitLocker going off

- **Hypothesis:** If a Secure Boot bypass succeeded, boot-configuration tampering (`bcdedit nointegritychecks/testsigning`, `mokutil --disable-validation`, ESP write) was followed within hours by HVCI or BitLocker transitioning from on to off — the BlackLotus payload chain disables OS protections from below before loading an unsigned kernel driver.
- **MITRE:** T1553.006 (Code Signing Policy Modification) → T1562.001 (Impair Defenses) → T1014 (Rootkit)
- **Data sources:** Defender XDR `DeviceProcessEvents` (boot LOLBins), `DeviceEvents` (DeviceGuard/BitLocker state), Windows `Win32_DeviceGuard` WMI, `manage-bde -status`, TPM/Measured Boot PCR[7].

## Prepare

HVCI and BitLocker state changes are infrequent on a stable fleet, so a transition is inherently interesting; the value of the hunt is the *sequence* — a boot-tamper action preceding the defense-off event. Build a per-device timeline of boot LOLBin executions and DeviceGuard/BitLocker state transitions. Note expected churn (BitLocker suspend during firmware updates is benign and usually self-resumes).

## Execute

```kql
let BootTamper =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("nointegritychecks","testsigning","DISABLE_INTEGRITY_CHECKS"))
         or (FileName =~ "mokutil.exe" and ProcessCommandLine has "--disable-validation")
    | project TamperTime = Timestamp, DeviceName, TamperCmd = ProcessCommandLine;
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("HypervisorEnforcedCodeIntegrity","CodeIntegrity","BitLocker")
| join kind=inner BootTamper on DeviceName
| where Timestamp between (TamperTime .. TamperTime + 24h)
| project TamperTime, DefenseEventTime = Timestamp, DeviceName, TamperCmd, ActionType, AdditionalFields
| order by DefenseEventTime desc
```

## Act / Analyze

A boot-tamper command followed by HVCI or BitLocker going off on the same host is a strong below-OS-compromise signal — isolate, capture memory before reboot, and verify the actual posture with `Get-CimInstance Win32_DeviceGuard` and `manage-bde -status`. Confirm Secure Boot ground truth (`Get-SecureBootUEFI`) rather than the OS boolean, and check PCR[7] for an unexplained boot-policy change. If confirmed, eradication is ESP rebuild + firmware re-flash, not a reimage. Promote the bcdedit-integrity-disable variant to a paging analytic — it is near-zero FP outside driver-development hosts.
