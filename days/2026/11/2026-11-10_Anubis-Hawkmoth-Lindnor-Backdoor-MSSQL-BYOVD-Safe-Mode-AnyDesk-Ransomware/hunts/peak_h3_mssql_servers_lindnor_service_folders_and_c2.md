# PEAK hunt H3 - SQL Servers: Lindnor-style services in look-alike folders and outbound 443 to rare hosts

## Prepare

- **Hypothesis:** a Microsoft SQL Server host runs an unfamiliar backdoor service (Lindnor-style) from a folder made to resemble a legitimate vendor directory (a Chrome component unpacker or VMware folder) and beacons over port 443 to a primary or fallback C2.
- **Why:** Symantec (Broadcom, 2026-11-05) reports that the first indicator of the Anubis intrusion was the new backdoor Backdoor.Lindnor on the only two SQL Servers among affected systems, apparently running as a service: `healthcontroller64.exe` (folder resembling a Chrome component unpacker directory) and `svchelper.exe` (VMware folder). Lindnor sends process ID, Windows version, its own path, computer name, user name, domain and logon server, and has primary and fallback C2 on 443. Published hosts: `msrcontrib[.]com`, `cfgsync-relay.eastus.cloudapp.azure[.]com` (role per host not given). Lindnor was also seen on two unrelated networks without ransomware, so a hit is not proof of imminent ransomware.
- **Honesty:** derived from the Symantec report as relayed by GBHackers and Cyber Security News (2026-11-09); no first-hand sample analysis. Initial access, the MSSQL abuse method (xp_cmdshell or otherwise), exact paths, service names, parent processes, IPs and URIs are NOT published. Steps 2-4 below are generic, inventory-based hunting, low confidence by design.
- **Scope:** all SQL Server hosts (populate `<add_known_sql_server_hosts>`; k3 also discovers hosts running `sqlservr.exe`), 30 days of service, file, process, network and DNS telemetry.
- **Confidence:** high for the two published hosts and the three Lindnor hashes; low for the behavioural blocks.

## Execute

**Data sources / content:** `kql/k3_mde_mssql_hosts_new_services_rare_folders_and_c2_domains.kql`, `kql/k2_mde_lindnor_anubis_byovd_hashes_and_names.kql`, `suricata/lindnor_c2_domains.rules` (sids 9980001-9980003), `sigma/02_anubis_lindnor_edr_killer_and_payload_process.yml`.

1. Run k3; any `C2 domain DNS` / `C2 domain connection` row is a priority-one lead. Match only the exact Azure host - never block or alert on `cloudapp.azure.com` broadly.
2. Inventory services on every SQL Server and diff against the build baseline; flag services whose binary lives under a folder named like Chrome / Google / VMware but is not signed by that vendor:

```powershell
# Author: Jarmi
Get-CimInstance Win32_Service |
  Select-Object Name, DisplayName, StartMode, State, StartName, PathName |
  ForEach-Object {
    $exe = ($_.PathName -replace '^"([^"]+)".*$','$1') -replace '\s+-.*$',''
    $sig = if (Test-Path $exe) { Get-AuthenticodeSignature $exe } else { $null }
    [pscustomobject]@{ Name=$_.Name; Path=$exe; Signer=$sig.SignerCertificate.Subject; Status=$sig.Status }
  } | Where-Object { $_.Path -match 'VMware|Chrome|Google' -and $_.Signer -notmatch 'VMware|Broadcom|Google' }
Get-ChildItem -Path C:\ -Recurse -Force -Include healthcontroller64.exe,svchelper.exe,powerhost.exe,eventwatcher.exe,volumeproxy.exe -ErrorAction SilentlyContinue |
  Get-FileHash -Algorithm SHA256
```

3. On each SQL Server, review whether `xp_cmdshell`, OLE Automation procedures or CLR are enabled and who changed them (a generic MSSQL-abuse hint, not a published Lindnor fact):

```sql
-- Author: Jarmi
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', 'clr strict security');
```

4. Build a 30-day destination inventory of outbound 443 from SQL Servers (they rarely browse the internet) and review destinations seen from only one or two hosts, with the initiating process.
5. Correlate with H1 and H2 on the same hosts and time window.

## Act

- **Expected benign:** SQL Agent jobs or maintenance plans spawning `cmd.exe` / `powershell.exe`; genuine VMware Tools or Google updater services; backup agents and monitoring tools with outbound 443.
- **Action on match:** a published-hash or published-host match = confirmed Lindnor. Isolate the SQL Server (coordinate with the DBA to avoid data loss), capture memory, export the service registry key and binary, collect SQL Server error logs and `sys.configurations` change history, and reset the SQL service account and any credentials cached on the host.
- **Escalation:** hunt every SQL Server and the rest of the estate by hash and host; pivot to H1 / H2 for ransomware staging; report to CISA / national CERT if ransomware deployment is attempted.
- **Detections:** deploy Suricata 9980001-9980003 and DNS / proxy blocks for `msrcontrib.com` and the exact Azure host; alert on new services on SQL Servers.
- **Exit criteria:** every SQL Server service binary signed and baselined; no contact with the published hosts; unexplained outbound 443 destinations resolved.
- **Caveat:** C2 hosts rotate and the Azure host may be reassigned; the durable signal is an unsigned service in a vendor look-alike folder on a server that should not talk to the internet.
