# PEAK hunt H2 - OceanGate: Linux SparrowShell / AnnobinDoor / Reptile on edge servers, then RDP brute force and CopperAdu admin$ on Windows

## Prepare

- **Hypothesis:** CopperDragon's OceanGate cluster exploited an internet-facing Linux server, deployed AnnobinDoor (UPX-packed Go backdoor, internal name `annobinagent`, file `containerd-demo`, WebSocket / HTTP / TCP C2) and the modular SparrowShell backdoor (plugins decrypted to `/tmp/%x`, loaded with `dlopen`, run through `xmain`, then deleted; magic `0x11223344`; config stored as `<executable>_`) with a modified Reptile rootkit loaded via `init_module` (ioctl `0x0e0e0e0e`; files `xfs_rudp`, `aplk`), trojanized `ssh` / `sshd` to log credentials, tunnelled with FRPC / Chisel and scanned with ASimplePortScanner; then pivoted to Windows by RDP brute force until an administrator logon succeeded, and ran CopperAdu (`adu.exe`) to create `admin$` with password `Admin@123456`, set `LocalAccountTokenFilterPolicy=1`, start LanmanServer / LanmanWorkstation and open TCP 445 with firewall rule `RasiUwpApp`; followed by CopperList (`filst2.exe`), CopperLogger (Raw Input keylogger, hidden window `kbl`, loader `STI.DLL`), CopperLsa (`g.exe`, custom SSP in LSASS logging NTLM / Kerberos) and a WinDivert-based passive SparrowDoor (loader `hha.dll`) listening behind port 443.
- **Why:** Check Point Research (2026-11-10) describes OceanGate as Linux-first (2025-2026). Linux edge servers often have no EDR, so the first durable evidence is frequently the Windows pivot (RDP failures, a hidden `admin$` account, a new firewall rule). The WinDivert backdoor hides behind a legitimate port, so port-based firewall review will not find it.
- **Honesty:** roughly 40 percent of the Check Point report was read only through a model summary; hashes carry medium confidence. The exploited Linux CVEs, AnnobinDoor C2 addresses, the CopperLsa SSP DLL name and log path, and the WinDivert source IP are not published in what was read. No first-hand sample analysis. Indicators decay.
- **Scope:** Linux internet-facing servers (auditd, EDR for Linux if present, `/var/log/secure` or `/var/log/auth.log`), 30 days of Windows logon (4625 / 4624 type 10), account creation (4720), registry and firewall telemetry; government and critical-infrastructure networks first.
- **Confidence:** high for `admin$` + `Admin@123456` and the `RasiUwpApp` rule; medium for hashes and the Linux file names; low for generic `/tmp` plugin load heuristics.

## Execute

**Data sources / content:** `sigma/02_copperdragon_copperadu_admin_dollar_account_and_firewall_rule.yml`, `kql/k3_mde_copperadu_account_firewall_and_lsass_dump.kql`, `suricata/copperdragon_infrastructure.rules` (sids 9995005, 9995006), `yara/copperdragon_sparrow_artifacts.yar` (rules `CopperDragon_OceanGate_Linux_AnnobinDoor_SparrowShell`, `CopperDragon_Windows_Tooling_Strings`).

1. Linux triage on each internet-facing server (run from trusted static binaries; a Reptile-class rootkit hides files and processes from the host's own tools):

```bash
# Author: Jarmi
# Loaded modules vs on-disk list (hidden modules show up as gaps); taint flags hint at unsigned modules
cat /proc/modules | awk '{print $1}' | sort > /tmp/mods_proc.txt
cat /proc/sys/kernel/tainted
dmesg | grep -iE 'taint|module verification failed'
# Named OceanGate artefacts and SparrowShell config files ending in "_"
find / -xdev \( -name 'containerd-demo' -o -name 'xfs_rudp' -o -name 'aplk' \) -ls 2>/dev/null
find /tmp /var/tmp /dev/shm -xdev -type f -mmin -1440 -ls 2>/dev/null
# Trojanized ssh / sshd: compare against the package database
rpm -Vf /usr/sbin/sshd /usr/bin/ssh 2>/dev/null || debsums -s openssh-server openssh-client 2>/dev/null
# Tunnels and scanners
ps -eo pid,ppid,user,cmd | grep -iE 'frpc|chisel|containerd-demo|ASimplePortScanner' | grep -v grep
# auditd: module loads and dlopen-heavy short-lived files in /tmp
ausearch -sc init_module -sc finit_module -i 2>/dev/null | tail -50
```

2. YARA-sweep Linux binaries and `/tmp` (unpack UPX first: `upx -d -o /tmp/unpacked <file>`):

```bash
# Author: Jarmi
yara -r -s yara/copperdragon_sparrow_artifacts.yar /usr/bin /usr/sbin /usr/local /opt /tmp /var/tmp
```

3. Windows pivot: run k3 and Sigma 02; then look for RDP brute force from the Linux server's internal IP that ends in a success:

```kql
// Author: Jarmi
DeviceLogonEvents
| where Timestamp > ago(30d) and LogonType == "RemoteInteractive"
| summarize Failures = countif(ActionType == "LogonFailed"), Successes = countif(ActionType == "LogonSuccess"), Accounts = make_set(AccountName, 20) by DeviceName, RemoteIP
| where Failures > 20 and Successes > 0
| order by Failures desc
```

4. On each Windows candidate:

```powershell
# Author: Jarmi
Get-LocalUser | Where-Object { $_.Name -like '*$' } | Select-Object Name, Enabled, PasswordExpires, LastLogon
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName 'RasiUwpApp','ss1' -ErrorAction SilentlyContinue | Select-Object DisplayName, Direction, Action, Enabled
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages'
Get-Service | Where-Object { $_.Name -like '*divert*' -or $_.Name -like 'WinDivert*' }
Get-ChildItem C:\ -Recurse -Force -Include 'adu.exe','filst2.exe','g.exe','hha.dll','STI.DLL','WinDivert*.sys' -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256
```

## Act

- **Findings handling:** per host: initial Linux service exploited, rootkit presence (module list, taint), trojanized ssh files, tunnel endpoints, Windows hosts reached via RDP, `admin$` accounts, firewall rules, extra Security Packages entries, WinDivert driver.
- **Escalation:** a Reptile-class rootkit means the Linux host cannot be trusted - rebuild from known-good media, do not clean in place. Treat every credential typed through the trojanized `ssh` / `sshd` and every credential that touched LSASS on hosts with the custom SSP as compromised; rotate, including service accounts.
- **Detections:** promote Sigma 02 to production; alert on 4720 for any local account ending in `$`; alert on new LSA Security Packages and on WinDivert driver loads on servers that never needed them.
- **Exit criteria:** no hidden `$` local accounts; `LocalAccountTokenFilterPolicy` back to its baseline; `RasiUwpApp` / `ss1` rules removed; Linux edge hosts rebuilt and re-patched; RDP not exposed between server tiers without MFA.
- **Caveat:** names and passwords are easy to change; the durable signals are a new hidden local admin right after an RDP brute-force success, an LSA package change, and a kernel module load on an edge Linux server.
