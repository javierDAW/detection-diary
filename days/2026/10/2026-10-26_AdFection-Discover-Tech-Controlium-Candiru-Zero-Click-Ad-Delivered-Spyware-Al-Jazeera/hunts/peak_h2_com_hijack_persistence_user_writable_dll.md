# PEAK hunt H2 - per-user COM hijack persistence to a DLL in a user-writable path

## Prepare

**Hypothesis.** The Candiru Windows implant isolated by Al Jazeera persists through a COM hijack. A per-user class registration under HKCU Software Classes CLSID InprocServer32 that points to a DLL in AppData, Temp, ProgramData or Users Public is the host-side trace of that persistence, and also of many other malware families.

**Why second.** It is behaviour-based, so it survives a rebuilt implant with new hashes, domains and XOR key. It is also noisy, which is why it follows the network hunt.

**Scope.** Windows endpoints used by the high-risk users from H1 first.

**Data quality check first.** Confirm that registry events are collected (Sysmon EID 12 and 13, or `DeviceRegistryEvents`), and that the collection is not filtered to a short allowlist of keys.

## Execute

```kql
// Author: Jarmi
// Defender XDR: user-level COM InprocServer32 registrations to user-writable DLLs, rare across the fleet.
DeviceRegistryEvents
| where Timestamp > ago(90d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\Software\Classes\CLSID\" and RegistryKey endswith @"\InprocServer32"
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\ProgramData\", @"\Users\Public\") and RegistryValueData endswith ".dll"
| summarize Devices=dcount(DeviceId), First=min(Timestamp) by RegistryKey, RegistryValueData
| where Devices <= 2
| order by First desc
```

```powershell
# Author: Jarmi
# Read-only: list per-user InprocServer32 values that point outside Windows and Program Files, then check each DLL signature.
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
  $k = Join-Path $_.PSPath 'InprocServer32'
  if (Test-Path $k) { $v = (Get-ItemProperty $k).'(default)'; if ($v -and $v -notmatch '^(C:\\Windows|C:\\Program Files)') { [pscustomobject]@{Clsid=$_.PSChildName; Dll=$v; Sig=(Get-AuthenticodeSignature $v -ErrorAction SilentlyContinue).Status} } }
}
```

## Act on

- Unsigned DLL, creation time close to a browser session, rare across the fleet: escalate and image the host. Compare the DLL SHA256 with the Candiru sample in `iocs.csv`.
- Signed DLL from a known vendor: record as benign and add the vendor path to an allowlist.

## Knowledge

Record which software legitimately registers per-user COM servers in your estate so the rule can be tightened.
