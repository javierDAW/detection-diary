# PEAK hunt H1 - First-seen remote-access tools on executive, partner and assistant endpoints

## Prepare

**Hypothesis.** If a caller posing as IT staff persuaded a person to start a remote session, then a remote-access tool that this host has not run in the last 90 days (Quick Assist, AnyDesk, Zoho Assist, or Syncro, Atera or Splashtop from the FBI list) starts on an executive, partner or assistant endpoint, usually within an hour of an inbound call or a voicemail.

**Why first.** GuidePoint GRIT found no malware, no exploit and no encryptor in the leaked chats. The tool is the only host artefact on the victim endpoint, and it is a legitimate product.

**Scope.** Endpoints of named executives, partners, general counsel, cyber or privacy partners and their assistants, from 2026-02-01 (the first ledger entry is 2026-02-06). GuidePoint reports 20 firms posted on the roster between 2026-07-30 and 2026-09-04.

**Data quality check first.** Confirm process creation is logged on these endpoints and retained for 90 days, and that your own help desk tool is on the exclusion list.

## Execute

```kql
// Full query in kql/k1. First-seen logic against a 90-day baseline.
let tools = dynamic(["quickassist.exe", "anydesk.exe", "atera", "splashtop", "syncro", "zohoassist", "za_connect"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where tolower(FileName) has_any (tools)
| summarize FirstRun = min(Timestamp) by DeviceName, FileName
```

```powershell
# Author: Jarmi
# Per-host check of AnyDesk traces and installed remote-support software (run on the suspect host, read-only).
Get-ChildItem "$env:ProgramData\AnyDesk\ad_svc.trace", "$env:APPDATA\AnyDesk\ad.trace" -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length
Get-Package -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'AnyDesk|Zoho|Atera|Splashtop|Syncro' } | Select-Object Name, Version
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'; StartTime=(Get-Date).AddDays(-14)} -ErrorAction SilentlyContinue | Select-Object -First 20 TimeCreated, Message
```

## Act

1. For every first-seen hit, ask the user and the help desk whether a ticket exists. No ticket means treat the session as hostile.
2. Pull the telephony record (inbound call, voicemail, Teams external call) for the user in the hour before the first run.
3. Check what the session touched: file shares opened, browser uploads, archive creation, in the hour after.
4. Contact legal and the FBI contact the firm already has if exfiltration is plausible; GuidePoint says to preserve voicemails, caller IDs and remote-session logs.

## Knowledge

- Result of this hunt: record the hosts, the tool, the ticket status and the call record.
- Tuning: add the sanctioned help desk tool to the exclusion list; raise a standing alert for the first execution of any tool in the list on the scoped endpoints.
- Source conflicts: KELA lists Zoom, Teams, Quick Assist, WinSCP and Rclone; GuidePoint lists AnyDesk, Zoho, Quick Assist and found no WinSCP or Rclone. Hunt for both lists.
