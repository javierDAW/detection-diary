# PEAK Hunt H3 — Rapid Bulk Exfiltration Following RMM Session Establishment

## Hypothesis

A workstation that recently installed a non-baseline RMM tool generated > 100 MB of outbound
network traffic to a public IP within 30 minutes of the RMM process starting. This matches the
SRG / Luna Moth modus operandi of immediate bulk exfiltration after remote access is established.

## Prepare

**Relevant telemetry**:
- Defender XDR DeviceProcessEvents + DeviceNetworkEvents
- NetFlow / proxy outbound byte counters
- SIEM aggregation by process + destination IP + time window

**Scope**: All Windows hosts, 14-day lookback. Focus on workstations with document access to privileged matter files.

## Execute

**Step 1 — RMM process + outbound volume correlation (Defender XDR)**:

```kql
let rmm = dynamic([
    "ScreenConnect.WindowsClient.exe","ScreenConnect.ClientService.exe",
    "zohoassist.exe","ITSPlatform.exe","itarian.exe","AnyDesk.exe"
]);
let RmmStart = DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ (rmm)
| project DeviceId, RmmTime=Timestamp, RmmFile=FileName, AccountName;
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (rmm)
| where RemoteIPType == "Public"
| summarize TotalSent=sum(SentBytes), DestCount=dcount(RemoteIP),
    Destinations=make_set(RemoteIP, 5)
    by DeviceId, InitiatingProcessFileName, bin(Timestamp, 5m)
| where TotalSent > 20971520  // 20 MB per 5-min window as first-pass threshold
| join kind=inner RmmStart on DeviceId
| where Timestamp between (RmmTime .. (RmmTime + 30m))
| project DeviceId, AccountName, RmmFile, RmmTime, ExfilWindow=Timestamp,
    TotalSentMB=round(TotalSent/1048576.0, 2), DestCount, Destinations
| order by TotalSentMB desc
```

**Step 2 — File staging prior to exfil (DeviceFileEvents)**:
```kql
// Look for bulk file copy / archive creation near the RMM install time
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileCopied","FileRenamed")
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
    or FolderPath has_any (@"AppData\Local\Temp", @"Users\Public")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ (rmm_processes)  // reuse rmm list from above
    | project DeviceId, RmmTime=Timestamp
  ) on DeviceId
| where Timestamp between (RmmTime .. (RmmTime + 30m))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, RmmTime
| order by Timestamp asc
```

## Analyze

- > 20 MB outbound per 5-minute window from an RMM process is anomalous in any law firm context.
- Archive creation (zip/7z) in temp or public paths prior to the outbound spike confirms staging.
- The 30-minute window is empirically derived from FBI Flash 260526; extend to 60 minutes for first pass.
- Compare destination IPs against threat intelligence (VirusTotal, ThreatFox) and fast flux indicators.

## Report

- Escalate immediately if threshold is breached. Contain the workstation before analyzing — exfil may still be ongoing.
- Collect: RMM session logs, MFT/INDX for the staging path, NetFlow full export, DNS cache.
- Notify legal counsel regarding potential privilege breach obligations before external notification.

## References

- [FBI IC3 Flash 260526](https://www.ic3.gov/CSA/2026/260526.pdf)
- [Resecurity SRG Fast Flux](https://www.resecurity.com/blog/article/silent-ransom-group-srg-uncovering-dns-fast-flux-infrastructure)
