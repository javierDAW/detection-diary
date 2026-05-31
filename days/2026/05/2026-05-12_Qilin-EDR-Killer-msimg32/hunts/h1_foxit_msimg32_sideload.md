# Hunt H1 — FoxitPDFReader as a side-load vehicle for Qilin EDR Killer

## Hypothesis

`FoxitPDFReader.exe` running from a non-install path (Downloads, Desktop, Temp, AppData) and loading a co-located `msimg32.dll` is highly anomalous. Legitimate Foxit installs live under `C:\Program Files\Foxit Software\` or `C:\Program Files (x86)\Foxit Software\`. The bundle observed by Cisco Talos in Qilin operations is a side-load-ready kit: signed Foxit binary plus a malicious `msimg32.dll` placed next to it.

## Why this discriminates

- Microsoft, vendor and managed installers always place application binaries in `Program Files`.
- Foxit, when present, imports `msimg32.dll` by name. The OS loader satisfies the import from `C:\Windows\System32\msimg32.dll` unless an attacker drops a same-named DLL adjacent to the executable (search-order hijacking).
- The combination of (a) Foxit out of `Program Files` and (b) `msimg32.dll` co-located with it is the structural signature of the bundle.

## Expected benign vs malicious

- **Benign:** developer evaluating Foxit portable in a sandbox VM; an ad-hoc tooling folder maintained by an internal team.
- **Malicious:** the user double-clicks a phishing payload, Foxit launches from `Downloads` or `Temp`, the malicious `msimg32.dll` is loaded, and within minutes the host shows a `rwdrv.sys` or `hlpdrv.sys` driver load, followed by silence in EDR telemetry.

## Action on match

1. Hash the loaded `msimg32.dll` and check against the known IOC `7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497`. If match → escalate as confirmed Qilin / Warlock activity.
2. Look for kernel driver service install events (`sc.exe create rwdrv`, `sc.exe create hlpdrv`) on the same host within 30 minutes.
3. Pull a RAM dump immediately — Stages 2-4 of the loader live in memory and are the only way to recover the embedded EDR driver list.
4. Isolate the host (do not power off).

## Query — Defender XDR

```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "FoxitPDFReader.exe"
| where FileName =~ "msimg32.dll"
| where not(InitiatingProcessFolderPath has_any ("\\Program Files\\", "\\Program Files (x86)\\"))
| project Timestamp, DeviceName, InitiatingProcessFolderPath, FolderPath, SHA256
```

## Reference

- [Qilin EDR killer infection chain — Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/)
