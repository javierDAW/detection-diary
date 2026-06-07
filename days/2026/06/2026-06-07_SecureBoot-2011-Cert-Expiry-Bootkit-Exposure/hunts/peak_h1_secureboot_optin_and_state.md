# PEAK Hunt H1 — Secure Boot opt-in / state gaps ahead of the frozen-KEK window

- **Hypothesis:** If a device is drifting toward the June 24 2026 frozen-KEK condition, it is missing the managed-transition opt-in (`MicrosoftUpdateManagedOptIn=0x5944`) or its Secure Boot state registry was flipped out of band. A device that never opts in keeps the expiring 2011 KEK, and after expiry its DBX can never receive a new bootkit revocation.
- **MITRE:** T1553.006 (Subvert Trust Controls: Code Signing Policy Modification) → T1542.001 (Pre-OS Boot: System Firmware) → T1112 (Modify Registry)
- **Data sources:** Defender XDR `DeviceRegistryEvents`; Windows Security 4657 (registry value change) on `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`; firmware-aware agent reading `Get-SecureBootUEFI KEK` for ground truth.

## Prepare

Inventory the fleet's intended migration tooling and change windows (GPO/Intune Settings Catalog/MECM). Build a watchlist of servicing parents (`TiWorker.exe`, `TrustedInstaller.exe`). Note: the OS registry state is a *proxy* — true KEK generation only comes from reading the UEFI variable. Stand up a collector (firmware-aware agent or a scripted `Get-SecureBootUEFI KEK` sweep) for confirmation.

## Execute

```kql
DeviceRegistryEvents
| where Timestamp > ago(45d)
| where RegistryKey has @"\Control\Secureboot"
| where RegistryValueName in~ ("MicrosoftUpdateManagedOptIn","UEFISecureBootEnabled")
| extend ServicingParent = InitiatingProcessFileName in~ ("TiWorker.exe","TrustedInstaller.exe","svchost.exe")
| project Timestamp, DeviceName, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ServicingParent
| order by Timestamp desc
```

For the inverse (devices that have NOT opted in), pivot to your CMDB/Intune: list managed Windows devices with no `MicrosoftUpdateManagedOptIn` write in the last 45 days — those are the migration laggards.

## Act / Analyze

A write by a non-servicing parent (interactive shell, unknown binary), or a `UEFISecureBootEnabled` flip to 0, is a tamper candidate — isolate and run the UEFI-variable IR steps. The larger finding is usually the population of devices with **no** opt-in: rank by exposure (internet-facing, privileged, EOL hardware that will never get an OEM firmware update) and drive the migration. Confirm the truth on a sample with `Get-SecureBootUEFI KEK` (2011 vs 2023). Pivot to H2 if any device also shows ESP writes.
