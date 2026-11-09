# PEAK hunt H1 - ftp.exe .ico script LNK chain and scheduled task masquerading as a Microsoft / BIOS update

## Prepare

- **Hypothesis:** a user opened a BITTER (TA397) lure LNK that launched `ftp.exe` with an argument pointing at an `.ico` file (`res.ico` / `icon.ico`); the ftp `!` shell escape (example printed: `!more res.ico`) piped the .ico "script" into `cmd`, which created a scheduled task disguised as a Microsoft (or BIOS) update that runs `curl` against C2 and stores downloaded commands in `err.log`.
- **Why:** FortiGuard Labs (2026-11-02) reports this binary-less chain against South Asian government, energy and engineering organisations (telemetry also in Southeast Asia and South Korea), attributed to BITTER with high confidence. It needs no RAT on disk, so file-hash detection misses it; operators change commands server-side, so the persistence task is the durable artefact.
- **Honesty:** derived from secondary reports of the FortiGuard Labs (Fortinet) 2026-11-02 research ("BITTER expands its arsenal with PapRAT") as relayed by Infosecurity Magazine, GBHackers, Hackread, Cyberpress, SOC Prime, OffSeq/OTX; the primary Fortinet blog was not read; no first-hand sample analysis. The exact LNK command line, task names, install paths, IPs, C2 ports and user agents are not published. Indicators decay.
- **Scope:** 30 days of Defender XDR process, file and scheduled-task telemetry on Windows endpoints; prioritise diplomacy, government, energy and engineering users and anyone handling Belt and Road / bilateral-meeting correspondence.
- **Confidence:** high for `ftp.exe` with an `.ico` argument; medium for the task-name heuristic (SOC Prime's `MicrosoftUpdatesupdates11678` is a simulation name, NOT an observed one).

## Execute

**Data sources / content:** `sigma/01_bitter_ftp_exe_ico_argument_lnk_chain.yml`, `kql/k1_mde_ftp_exe_ico_and_msi_lure_process_chain.kql`, `kql/k3_mde_scheduled_task_ms_update_masquerade_and_rat_binaries.kql`, `yara/bitter_paprat_wmrat_artifacts.yar` (rule `BITTER_FtpExe_Ico_Script_Or_LNK`).

1. Run k1 and baseline every `ftp.exe` execution in the estate (it is rare on modern endpoints); flag any with `.ico` on the command line, parent `explorer.exe`, or child `cmd.exe` / `more.com` / `curl.exe` / `schtasks.exe`.
2. Run k3 and review every non-`\Microsoft\Windows\` task whose name contains Microsoft / Update / BIOS and whose action runs `curl`, `cmd`, `powershell` or a script.
3. On each candidate host, enumerate tasks and look for curl actions and the staging files:

```powershell
# Author: Jarmi
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } |
  ForEach-Object { [pscustomobject]@{ Name=$_.TaskName; Path=$_.TaskPath; Exec=($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ' } } |
  Where-Object { $_.Exec -match 'curl|cmd|powershell|ftp|\.ico' }
Get-ChildItem -Path C:\Users -Recurse -Force -Include err.log,abc.pdf,res.ico,icon.ico -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTime, LastWriteTime
```

4. Scan the `.ico` / `.lnk` files found with the YARA rule (a real icon starts with bytes `00 00 01 00`; a text .ico is a red flag):

```bash
# Author: Jarmi
yara -s yara/bitter_paprat_wmrat_artifacts.yar /evidence/<host>/Users/
```

5. Correlate with H3: any host with this chain should also show DNS / HTTP to the campaign domains.

## Act

- **Findings handling:** per host: LNK path and origin (mail attachment, RAR, VHDX), task name / action / trigger interval, presence of `err.log` and `abc.pdf`, first and last C2 contact.
- **Escalation:** a confirmed ftp.exe .ico chain = active BITTER intrusion. Isolate the host, export the task XML and `err.log` before deleting anything (it holds the operator commands), check whether `abc.pdf` recon output was uploaded, and pivot to H2 (follow-on PapRAT / WmRAT delivery).
- **Detections:** promote Sigma 01 to production; consider an ASR / WDAC block on `ftp.exe` for users with no business need.
- **Exit criteria:** every ftp.exe execution with an .ico argument explained; no unexplained update-like tasks running curl or cmd; YARA sweep of user profiles clean.
- **Caveat:** filenames and task names are trivially changed; the behaviour (ftp.exe launched from a LNK, shell escape, curl in a task) is the durable signal.
