# PEAK H1 — PDF-icon executable extracted from a tax-themed archive

## Hypothesis

A workstation in the finance, HR or legal function received a tax-themed RAR/ZIP
attachment in the past seven days, extracted an executable that uses a PDF icon
(`Click File.exe`, `BillReceipt.exe`, `Review the file.exe`, `statement.exe`,
`GST Suvidha.exe`), and either spawned `pythonw.exe -m appclient` or wrote a
`%LOCALAPPDATA%\appclient\` directory within thirty minutes of double-click.

## Why this discriminates

Silver Fox engineered the tax lure for exactly the workforce roles that handle
tax correspondence as part of their job — they will plausibly double-click an
attachment titled `ITD-Notice.rar`. The pivot from "tax-themed archive" to "PDF
icon EXE" is the first step in the kill chain that crosses out of standard user
behaviour: legitimate tax authorities deliver PDFs, never bundled `.exe` files.
The follow-up appearance of `pythonw.exe -m appclient` is the canonical
persistence anchor for ABCDoor and has no benign baseline in this organisation
type.

## Expected benign vs malicious

Expected benign hits are essentially zero outside dedicated malware-analysis
hosts. A FinOps team using a custom Python tool literally named `appclient` is a
plausible but rare false positive — the path anchor `C:\ProgramData\Tailscale\`
or `%LOCALAPPDATA%\appclient\` cleanly discriminates the malicious case.

## Data sources

- Defender XDR `DeviceFileEvents` (file drops in Downloads / Temp / Outlook).
- Defender XDR `DeviceProcessEvents` (parent process WinRAR / 7zG / Outlook).
- Defender XDR `DeviceRegistryEvents` (HKCU Run\AppClient).
- Email gateway (Proofpoint, Microsoft Defender for Office 365) — tax-themed
  subject + RAR/ZIP attachment + sender SendGrid sub-domain.

## KQL — chained query

```kql
let lures = dynamic(["Click File.exe","BillReceipt.exe","Review the file.exe","statement.exe","statement verify .exe","Related material.exe","GST.pdf.exe","GST Suvidha.exe","GSTSuvidha.exe"]);
let drops = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName in~ (lures)
| project DropTime=Timestamp, DeviceId, DeviceName, FileName, FolderPath, InitiatingProcessFileName;
let runs = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("pythonw.exe","python.exe")
| where ProcessCommandLine has_all ("-m","appclient")
| project ExecTime=Timestamp, DeviceId, ProcessCommandLine;
drops
| join kind=inner (runs) on DeviceId
| where ExecTime between (DropTime .. (DropTime + 30m))
| project DropTime, ExecTime, DeviceName, FileName, FolderPath, ProcessCommandLine
```

## Action on match

1. Isolate the host (Defender LiveResponse `isolate-machine`).
2. Capture RAM before reboot (`winpmem` to external storage).
3. Pull HKCU\Run, HKCU\Software\CarEmu, and the AppClient scheduled task XML.
4. Pull `%LOCALAPPDATA%\appclient\`, `%LOCALAPPDATA%\applogs\`,
   `C:\ProgramData\Tailscale\`, and `%TEMP%\appclient_*.zip`.
5. Hunt laterally on every host that received the same email (recipient
   inventory from M365 message-trace) — RustSL geofencing means only some hosts
   will detonate, but the dropper is everywhere the email went.
6. Reset the user's Microsoft 365 credentials (the implant has clipboard,
   screen, keyboard control — assume password capture).
7. Hand the binary to the malware team for the `appclient.core.cp*-win_amd64.pyd`
   decompilation track.
