# PEAK Hunt H2 — backup / AV / SQL service termination before encryption

**Hypothesis.** If the Kyber encryptor reached backup infrastructure, then services whose names match `veeam`, `vss`, `backup`, `sql`, or `msexchange` will be stopped en masse on a host immediately before a spike in file modifications — Kyber forces the locale to en-US and stops these services to release locked backup/database files and remove restoration capability.

**ATT&CK.** T1489 (Service Stop).

## Prepare

- Telemetry: Service Control Manager events (System log 7036/7040), Sysmon EID 1 / 4688 for command-line stops, and `DeviceProcessEvents`.
- Scope: backup servers (Veeam/VBR), SQL hosts, Exchange, and file servers. Baseline planned maintenance that stops these services.

## Execute

```kql
let TargetSvc = dynamic(["veeam","vss","backup","msexchange","sqlserver","mssql","sqlwriter"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("net.exe","net1.exe","sc.exe","taskkill.exe","powershell.exe","pwsh.exe")
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd has_any ("stop","stop-service","delete","/f")
| where Cmd has_any (TargetSvc)
| summarize Stops = count(), Commands = make_list(ProcessCommandLine, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by DeviceName, AccountName, bin(Timestamp, 30m)
| order by Stops desc
```

## Analyze

- Correlate the stop window with file-modification volume (`DeviceFileEvents` rename/create spikes) on the same host. Service stops of backup/SQL services followed within minutes by mass file change is the pre-encryption fingerprint.
- Native SCM-API stops may not produce a process event — confirm with System log 7036 ("entered the stopped state") for the same service names.

## Act

- If confirmed: isolate; confirm whether backups are immutable/off-host and unreachable from the compromised admin context; do not restore onto a suspect host.
- Treat any host that stopped Veeam/SQL services as in-scope for the full Kyber chain (recovery inhibition, Hyper-V stop, encryption).
