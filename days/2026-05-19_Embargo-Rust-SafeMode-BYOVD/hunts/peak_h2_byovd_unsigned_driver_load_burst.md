# PEAK H2 — BYOVD non-canonical driver load + AV process stop burst (Embargo MS4Killer T1068)

## Hypothesis

An Embargo MS4Killer instance has been executed on the host. It drops
`probmon.sys` (signed by the revoked ITM System Co., LTD certificate) under
the rotated names `Sysprox.sys`, `Sysmon64.sys` or `Proxmon.sys`, registers
a kernel-mode service via `CreateServiceW`, writes minifilter altitude/instance
keys, and loads the driver via `FilterLoad`. Immediately afterwards it uses
the driver's `FilterSendMessage` interface to terminate AV processes from
kernel.

## Why this discriminates

A kernel driver loaded from a path outside `\Windows\System32\drivers\` is
already a strong anomaly — Windows installs legitimate drivers in that
directory exclusively. The combination of (a) a kernel driver loaded from a
non-canonical path, (b) within 15 minutes, the crash or termination of an
AV/EDR process is operationally indistinguishable from a BYOVD attack and is
a known ransomware pre-encryption signal. Joins H2 with the per-family
`byTechnique/t1068/` driver catalogue to enrich confidence.

## Expected benign vs malicious

| Signal | Benign | Malicious |
|---|---|---|
| Driver load outside `\System32\drivers\` | Some signed Microsoft drivers in WinSxS during patch staging; uncommon on production | `Sysprox.sys` / `Sysmon64.sys` / `Proxmon.sys` from `\Windows\System32\drivers\` *with the wrong signer* or from `\Windows\` directly |
| AV process termination | Scheduled AV restart; legitimate update | Termination without restart, no service-change event, no Windows Update event |
| Signed by revoked cert | None on a properly patched host | ITM System Co., LTD signer present |

## Action on match

1. EDR isolate.
2. Capture RAM + driver binary on disk.
3. Hash-check driver against the LOLDrivers catalogue and against the
   ESET-published probmon.sys v3.0.0.4 SHA1
   `7310D6399683BA3EB2F695A2071E0E45891D743B`.
4. Sweep the fleet for the same driver hash and signer.
5. If signer matches ITM System Co., LTD across multiple hosts, the operator
   has likely standardised on `probmon.sys` for this campaign — pivot to
   `byActor/embargo/` to confirm.

## Queries

### Defender XDR — driver load from non-canonical path + AV stop ≤ 15 min

See [`kql/byovd_probmon_driver_load_defender_xdr.kql`](../kql/byovd_probmon_driver_load_defender_xdr.kql).

### Sysmon EID 6 — kernel driver load with revoked signer

```text
EventID:6 (Signature:"ITM System Co.,LTD" OR Hashes:"*7310D6399683BA3EB2F695A2071E0E45891D743B*")
```

### Local PowerShell — installed kernel drivers outside canonical path

```powershell
Get-CimInstance Win32_SystemDriver |
    Where-Object { $_.PathName -notlike '*\System32\drivers\*' -and $_.PathName -notlike '*WUDFRd*' -and $_.State -eq 'Running' } |
    Select-Object Name, PathName, State, StartMode
```

## False positives to triage

- Legacy ITM System ProBuMain installations on industrial workstations may
  legitimately load `probmon.sys`. Cross-check with installed-software
  inventory and asset class.
- Custom HID/USB drivers from niche industrial vendors may live outside
  `\System32\drivers\`. Inventory-based allowlist resolves these.
