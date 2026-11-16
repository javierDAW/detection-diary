# PEAK hunt H3 - DarkWire: CopperLoader side-loading, renamed SoftEther, CopperDNS / CopperProxy C2 and LSASS dumps saved as 1.png

## Prepare

- **Hypothesis:** CopperDragon's DarkWire cluster (telecom and government in Latin America, mid-2025 onward) staged CopperLoader through DLL side-loading pairs (`ncpmif32.dll` / `ncptrcw.exe`, `winfsp.dll` / `fsptool.exe`, `libvlccore.dll` / `vlc.exe`, `DukeQt.dll` / `gethwid.exe`, `zCrashReport64.dll` / `zCrashReport64.exe`) in folders such as `C:\Program Files\7-Zip\Lang`, `C:\Windows\debug`, `C:\Windows\System32`, `C:\ProgramData\vmware\logs`, `C:\ProgramData\Oracle\Java`, `C:\ProgramData\USOShared`, `C:\ProgramData\Waves`; the loader decrypted an RC4 `.dat` next stage (CopperDoor, aka SparroWocky) in memory; C2 ran over DNS MX queries (CopperDNS, mostly Windows servers in AS20473 / Vultr, port 6532, reused TLS certificate SHA-256 `ee4a8b81fe3864582efc27a77f806990e2602dcc36447ddda4b3a230a473d575`) and the shared domain `amelicen[.]com`; tunnelling used CopperProxy (SOCKS5, firewall rule `ss1`), PyProxy (PyInstaller UDP relay) and SoftEther VPN renamed `vmtoolsd.exe` / `csrss.exe`; lateral movement used SMB and `wmiexec`; credentials came from LSASS via `comsvcs.dll`, `dep.dll` and CopperLsass (`slave.dll` loaded into LSASS), with the dump encrypted by a custom "SUB-XOR-ADD" routine and renamed `1.png`.
- **Why:** Check Point Research (2026-11-10) reports DarkWire as the telecom-focused cluster of the CopperDragon ecosystem. Signed host EXEs and memory-only payloads defeat hash blocking; the stable signals are image loads from odd folders, DNS MX volume from servers, process names that do not match their path, and LSASS access followed by an image-extension file.
- **Honesty:** roughly 40 percent of the Check Point report was read only through a model summary; the CopperDNS certificate hash and the domain carry medium confidence. The pair-to-folder mapping, CopperDNS server IPs, CopperDNS query format, `dep.dll` invocation and the `slave.dll` path are not published in what was read. No first-hand sample analysis. Indicators decay.
- **Scope:** 30 days of Defender XDR image-load, process, file and network telemetry on Windows servers and workstations; DNS server logs (query type MX) and NetFlow for 90 days; telecom operators, ministries and government agencies in Latin America first, then any organisation in the CopperDragon victimology.
- **Confidence:** high for LSASS dumps via comsvcs with a `1.png` output and for renamed SoftEther outside System32; medium for the side-loading pairs (several are legitimate products); low for DNS MX volume and port 6532 heuristics.

## Execute

**Data sources / content:** `sigma/03_copperdragon_darkwire_sideload_host_exe_with_dll_outside_system_paths.yml`, `sigma/03b_copperdragon_darkwire_renamed_softether_vmtoolsd_csrss_outside_system_paths.yml`, `sigma/04_copperdragon_lsass_dump_comsvcs_minidump_png_output.yml`, `sigma/02_copperdragon_copperadu_admin_dollar_account_and_firewall_rule.yml` (`ss1` rule), `kql/k2_mde_campaign_domains_and_ips_90d.kql`, `kql/k3_mde_copperadu_account_firewall_and_lsass_dump.kql`, `suricata/copperdragon_infrastructure.rules` (sid 9995003).

1. Side-loading sweep: list every load of the five DLL names and keep those where the host EXE or DLL sits in a published staging folder or in ProgramData / Temp / Public:

```kql
// Author: Jarmi
let Pairs = datatable(HostExe:string, Dll:string)[
  "ncptrcw.exe","ncpmif32.dll", "fsptool.exe","winfsp.dll", "vlc.exe","libvlccore.dll",
  "gethwid.exe","dukeqt.dll", "zcrashreport64.exe","zcrashreport64.dll"];
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| extend HostExe = tolower(InitiatingProcessFileName), Dll = tolower(FileName)
| join kind=inner Pairs on HostExe, Dll
| where FolderPath has_any (@"\7-Zip\Lang\", @"\Windows\debug\", @"\ProgramData\", @"\Windows\System32\", @"\Users\Public\", @"\Temp\")
| project Timestamp, DeviceName, InitiatingProcessFolderPath, FolderPath, FileName, SHA256, InitiatingProcessSHA256
```

2. Renamed SoftEther: run Sigma 03b, then on candidates check signer and version info:

```powershell
# Author: Jarmi
Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'vmtoolsd.exe','csrss.exe' } |
  ForEach-Object { $f = $_.ExecutablePath; if ($f) { $s = Get-AuthenticodeSignature $f; [pscustomobject]@{ Pid=$_.ProcessId; Path=$f; Signer=$s.SignerCertificate.Subject; Product=(Get-Item $f).VersionInfo.ProductName } } }
Get-ChildItem 'C:\ProgramData\vmware\logs','C:\ProgramData\Oracle\Java','C:\ProgramData\USOShared','C:\ProgramData\Waves','C:\Windows\debug','C:\Program Files\7-Zip\Lang' -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.exe','.dll','.dat' } | Get-FileHash -Algorithm SHA256
Get-NetFirewallRule -DisplayName 'ss1' -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter
```

3. CopperDNS / C2: in DNS server logs, rank internal clients by MX query volume (workstations and most servers should send almost none); review long-lived TCP 6532 sessions to Vultr ranges (AS20473) and any server certificate with SHA-256 `ee4a8b81fe3864582efc27a77f806990e2602dcc36447ddda4b3a230a473d575` in Zeek `x509.log` / TLS inspection; run k2 for `amelicen[.]com`.
4. Credential access: run Sigma 04 and k3; then search for LSASS access followed by an image-extension file from a non-image process, and for `slave.dll` / `dep.dll` loads:

```kql
// Author: Jarmi
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("slave.dll", "dep.dll", "comsvcs.dll") and InitiatingProcessFileName in~ ("lsass.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
```

5. Lateral movement: look for `wmiexec`-style children of `WmiPrvSE.exe` (`cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<epoch>` output redirection) and SMB admin-share writes from the hosts found above.

## Act

- **Findings handling:** per host: side-loading pair and folder, `.dat` payload hash, tunnel tools (SoftEther, CopperProxy, PyProxy) and their peers, MX query volume, LSASS dump evidence and the `1.png` path, wmiexec sources and targets.
- **Escalation:** LSASS dumped = every credential cached on that host is compromised; reset, including krbtgt twice if a domain controller is affected. For telecom operators, involve the core-network team: the actor's interest is subscriber and lawful-intercept data. Report through the national CERT.
- **Detections:** promote Sigma 03, 03b and 04 to production; enable LSASS protection (RunAsPPL) and the ASR rule "Block credential stealing from the Windows local security authority subsystem"; alert on MX queries from non-mail servers.
- **Exit criteria:** no side-loading pairs in staging folders; no renamed SoftEther; `ss1` removed; no MX anomalies or TCP 6532 egress; credentials rotated; RunAsPPL enforced.
- **Caveat:** host / DLL pairs and folder choices change between intrusions; the durable signals are a signed vendor EXE running from a folder its vendor never uses, DNS MX traffic from servers, and an LSASS read followed by a renamed output file.
