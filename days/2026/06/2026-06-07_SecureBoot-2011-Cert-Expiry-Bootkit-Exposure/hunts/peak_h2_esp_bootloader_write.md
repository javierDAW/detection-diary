# PEAK Hunt H2 — EFI System Partition boot-component write correlated with a mount

- **Hypothesis:** If a bootkit was staged, a non-servicing process mounted the EFI System Partition to a drive letter and wrote a boot component (`bootmgfw.efi`, `bootx64.efi`, `grubx64.efi`, `shimx64.efi`). On a frozen-DBX device the staged signed-but-revoked binary is never blocked and runs pre-OS.
- **MITRE:** T1542.003 (Pre-OS Boot: Bootkit) → T1542.001 (System Firmware) → T1553.006 (Code Signing Policy Modification)
- **Data sources:** Defender XDR `DeviceFileEvents` + `DeviceProcessEvents`; Sysmon EID 11 (FileCreate) once the ESP is mounted; boot-config integrity tool.

## Prepare

The ESP is invisible to file telemetry until mounted to a drive letter, so the hunt pairs a `mountvol /S` (or `Mount-DiskImage`) event with subsequent writes under `\EFI\`. Baseline approved imaging/boot-repair tooling and OEM firmware agents that legitimately touch the ESP. Capture a known-good hash of `bootmgfw.efi` for the current patch level to diff against.

## Execute

```kql
let MountEvents =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "mountvol.exe" and ProcessCommandLine has " /S"
    | project MountTime = Timestamp, DeviceName, MountProc = InitiatingProcessFileName;
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\EFI\"
| where FileName in~ ("bootmgfw.efi","bootx64.efi","grubx64.efi","shimx64.efi")
| where InitiatingProcessFileName !in~ ("TiWorker.exe","TrustedInstaller.exe","bcdboot.exe","poqexec.exe")
| join kind=leftouter MountEvents on DeviceName
| where isnull(MountTime) or (Timestamp - MountTime) between (0min .. 30min)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, MountProc
| order by Timestamp desc
```

## Act / Analyze

Any write to `bootmgfw.efi` by an interactive shell is a near-certain bootkit-staging event — mount the ESP read-only, hash every `*.efi`, and diff `bootmgfw.efi` against known-good (BlackLotus rolls it back to a revoked older version). If the hash is an older signed boot manager, treat as confirmed: do not reimage — escalate to ESP rebuild plus firmware re-flash. Pivot to H3 to check whether HVCI/BitLocker were subsequently disabled.
