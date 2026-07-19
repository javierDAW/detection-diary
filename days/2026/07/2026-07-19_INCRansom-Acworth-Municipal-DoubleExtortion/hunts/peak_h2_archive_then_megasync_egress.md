# PEAK Hunt H2 -- Archive-Then-Exfiltrate Pattern (7-Zip/WinRAR -> MegaSync)

**Case:** INC Ransom / City of Acworth, GA (2026-07-19)
**MITRE:** T1560.001 (Archive via Utility), T1074 (Data Staged), T1537 (Transfer Data to Cloud Account)

## Hypothesis

INC Ransom stages collected data with 7-Zip/WinRAR and exfiltrates it via MegaSync
before detonating the encryptor. If active in this environment, we should observe
a host running an archive utility against a large or sensitive dataset, followed
within a short window by an outbound connection to Mega cloud-storage
infrastructure from that same host.

## Abstract

Correlate `DeviceProcessEvents` archive-utility execution (7z.exe, 7za.exe,
winrar.exe, rar.exe) against `DeviceNetworkEvents` connections to `mega.nz` /
`mega.co.nz` / megasync.exe process-attributed traffic on the same device within a
6-hour window. Servers and file-share hosts are the priority scope; workstation
noise should be filtered separately.

## Execute

See `kql/inc_ransom_megasync_exfil.kql` for the join query. Supplement with a
volume check: large outbound transfer size on the correlated connection (several
GB) strengthens the signal over a single small upload.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("mega.nz","mega.co.nz")
| summarize TotalBytes = sum(tolong(coalesce(column_ifexists("SentBytes",0),0))), Connections = count() by DeviceName, bin(Timestamp, 1h)
| where TotalBytes > 500000000 or Connections > 5
```

## Key results

Record: device name, archive tool + arguments (target directory reveals what was
staged), destination Mega account/URL if resolvable, transfer volume and duration,
and whether the same device later shows encryption-impact indicators
(`.INC` file renames, ransom-note drops).

## Interpret

True positive: archive → egress sequence on a server-tier host outside any known
backup/migration change window, especially if followed by impact-stage
indicators. False positive: an approved backup job that happens to use 7-Zip
staging plus a legitimate MegaSync business account -- confirm against your
sanctioned cloud-storage inventory before escalating.
