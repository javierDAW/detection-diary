# PEAK hunt H2 - VHDX / RAR lure, LNK-launched MSI with Type 194 CustomAction, and PapRAT / WmRAT binaries

## Prepare

- **Hypothesis:** a user mounted a BITTER lure VHDX (e.g. "Letter from the Ambassador - 11th Belt and Road Summit.vhdx") or opened a lure RAR (e.g. "Official Invitation Majilis 2026 Gala Dinner.rar"); a LNK started `Visa_Details.msi` (VHDX, hidden, with a decoy spreadsheet) or `Imp_Details.msi` (RAR -> URL shortcut -> LNK over WebDAV from rappellingaart[.]com) whose only logic is a Type 194 CustomAction that dropped PapRAT (`bruzsvc.exe`), which later fetched WmRAT (`vnces.exe`).
- **Why:** FortiGuard Labs (2026-11-02) documents both chains; Xcitium reads Type 194 as base 2 + flags 64 + 128 = asynchronous executable launched from the MSI Binary table, so nothing is installed and the payload runs while msiexec returns. WmRAT was previously documented by Proofpoint (Dec 2024).
- **Honesty:** derived from secondary reports of the FortiGuard Labs (Fortinet) 2026-11-02 research ("BITTER expands its arsenal with PapRAT") as relayed by Infosecurity Magazine, GBHackers, Hackread, Cyberpress, SOC Prime, OffSeq/OTX; the primary Fortinet blog was not read; no first-hand sample analysis. The exact LNK command line, task names, install paths, IPs, C2 ports and user agents are not published. Indicators decay.
- **Scope:** 30 days of Defender XDR process / file / device events on Windows endpoints; mail and web gateways for .vhdx, .rar and .url attachments.
- **Confidence:** high for the lure MSI names and `bruzsvc.exe` / `vnces.exe`; medium for generic VHDX-mount + msiexec correlation.

## Execute

**Data sources / content:** `sigma/02_bitter_msi_installer_visa_or_imp_details_msi.yml`, `kql/k1_mde_ftp_exe_ico_and_msi_lure_process_chain.kql`, `kql/k3_mde_scheduled_task_ms_update_masquerade_and_rat_binaries.kql`, `yara/bitter_paprat_wmrat_artifacts.yar` (rule `BITTER_PapRAT_PE`).

1. Run k1 (lure MSI + msiexec children) and k3 (bruzsvc.exe / vnces.exe file and process events).
2. Find VHDX / ISO mounts followed within minutes by msiexec from the mounted volume (Windows event `Microsoft-Windows-VHDMP-Operational` EID 1 / 12 if collected; in Defender, `DeviceEvents` and process paths on a new drive letter).
3. Review the MSI Installer log (Application log, source MsiInstaller, EID 1033 / 11707) for product names that match no software catalogue entry and were installed from a removable / virtual drive or a WebDAV path.
4. For any recovered MSI, list CustomActions and look for Type 194:

```bash
# Author: Jarmi
# msitools on a Linux analysis host
msiinfo export Visa_Details.msi CustomAction
msiinfo streams Visa_Details.msi
```

5. Check `bruzsvc.exe` version info (fake "Microsoft Corporation" / "Microsoft redistributables" with no valid Microsoft signature) and run the YARA PE rule on dropped binaries and the MSI Binary streams.
6. Pivot: hosts with WebDAV (`davclnt.dll` / `rundll32` WebDAV client) traffic to rappellingaart[.]com feed into H3.

## Act

- **Findings handling:** per host: lure container name and delivery vector, MSI name and CustomAction type, dropped paths and hashes, task created, WmRAT presence.
- **Escalation:** PapRAT exposes a remote shell, file upload / download, screenshots and (Rust build) PowerShell; treat as full hands-on-keyboard compromise. Isolate, capture memory before killing `bruzsvc.exe` / `vnces.exe`, collect the MSI, LNK, decoy and task XML, and review what data the user's account could reach.
- **Detections:** keep Sigma 02 in production; block .vhdx / .vhd / .iso attachments at the mail gateway and consider disabling automatic VHDX mount for standard users.
- **Exit criteria:** all lure MSI executions explained; no bruzsvc.exe / vnces.exe on disk; no unexplained msiexec children in user-writable paths.
- **Caveat:** filenames are lure-specific and change per wave; the Type 194-only MSI with no installable content is the durable trait.
