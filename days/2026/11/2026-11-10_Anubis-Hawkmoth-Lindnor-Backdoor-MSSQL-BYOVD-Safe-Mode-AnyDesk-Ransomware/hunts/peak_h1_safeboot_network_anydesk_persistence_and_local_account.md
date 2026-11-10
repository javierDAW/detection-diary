# PEAK hunt H1 - SafeBoot\Network service additions, AnyDesk on servers and new local accounts

## Prepare

- **Hypothesis:** an Anubis (Hawkmoth RaaS) affiliate, or any operator using the same playbook, registered a remote-access service (AnyDesk in the reported case) under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\` so it survives a reboot into Safe Mode with Networking, installed genuine AnyDesk and created a new local user added to a local group, as preparation for running ransomware while security tools are not loaded.
- **Why:** Symantec (Broadcom, 2026-11-05) reports that in an October 2026 intrusion on a U.S. organization a tool named `safemode.exe` ran, verbatim: `"CSIDL_SYSTEM\reg.exe" add HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AnyDesk /ve /t REG_SZ /d Service /f` (`CSIDL_SYSTEM` = the report's placeholder for System32). Security tools generally do not fully run in Safe Mode, so this key is a high-value pre-encryption signal. AnyDesk itself is legitimate, so hashes do not help; the SafeBoot key does.
- **Honesty:** derived from the Symantec report as relayed by GBHackers and Cyber Security News (2026-11-09); no first-hand sample analysis. The name of the new local account and its group are NOT published; initial access was not determined.
- **Scope:** 30 days of Defender XDR registry, process and account telemetry on all Windows servers first (SQL Server hosts in particular), then workstations.
- **Confidence:** high for an AnyDesk key under SafeBoot; medium for any other non-baselined SafeBoot service; low for account creation alone.

## Execute

**Data sources / content:** `sigma/01_anubis_anydesk_safeboot_network_registry.yml`, `kql/k1_mde_safeboot_network_anydesk_and_local_account.kql`, `yara/anubis_lindnor_artifacts.yar` (rule `Anubis_SafeMode_AnyDesk_SafeBoot_Registration`).

1. Run k1. Baseline the legitimate SafeBoot entries in the estate into `<add_known_safeboot_services>` and review every remaining key, highest severity first.
2. On each candidate host, enumerate SafeBoot entries and compare against a clean build of the same OS:

```powershell
# Author: Jarmi
foreach ($mode in 'Network','Minimal') {
  Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" |
    ForEach-Object { [pscustomobject]@{ Mode=$mode; Key=$_.PSChildName; Default=(Get-ItemProperty $_.PSPath).'(default)' } }
} | Where-Object { $_.Key -match 'AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera' -or $_.Default -eq 'Service' }
bcdedit /enum '{current}' | Select-String -Pattern 'safeboot'
Get-LocalUser | Sort-Object -Property Enabled -Descending | Select-Object Name, Enabled, LastLogon, PasswordLastSet
Get-LocalGroupMember -Group Administrators
```

3. Check whether a Safe Mode boot is already queued (`safeboot` value in the BCD output above) - that means encryption may be imminent.
4. Correlate the SafeBoot change time with AnyDesk first execution (k1 `AnyDeskFirst`) and any `UserAccountCreated` / `UserAccountAddedToLocalGroup` events within 24 h.
5. Sweep ProgramData, Temp and user profiles for the `safemode.exe`-like tool with the YARA rule and by hash `47a864736764112d7897c76e56d51111ce75b3e46fdbac6933df8a5b29507d17`.

## Act

- **Expected benign:** MSPs or help desks that deliberately enable AnyDesk in Safe Mode for remote recovery (should be documented and consistent across the fleet); backup / AV products registering their own SafeBoot service.
- **Action on match:** an AnyDesk (or other remote-tool) SafeBoot key on a server with no change record = treat as pre-ransomware staging. Isolate the host, remove any queued Safe Mode boot (`bcdedit /deletevalue {current} safeboot`) only after imaging, export the registry hive, disable the new local account, and collect AnyDesk logs (`%ProgramData%\AnyDesk\ad_svc.trace`, `%AppData%\AnyDesk\ad.trace`, `connection_trace.txt`) for the remote client ID and source IPs.
- **Escalation:** pivot to H2 (BYOVD / EDR killers dropped within about an hour of first activity) and H3 (Lindnor backdoor on SQL Servers). Declare a ransomware incident if any `.anubis` file or `restore files.txt` / `restore files.html` note appears.
- **Detections:** promote Sigma 01 to production on servers; add an alert on any new SafeBoot `Network` / `Minimal` key not in the baseline.
- **Exit criteria:** every non-baselined SafeBoot entry explained; no unexplained local accounts in privileged groups; AnyDesk present only where approved.
- **Caveat:** the tool name `safemode.exe` and the AnyDesk choice are trivially changed; the durable signal is a remote-access service being added to SafeBoot.
