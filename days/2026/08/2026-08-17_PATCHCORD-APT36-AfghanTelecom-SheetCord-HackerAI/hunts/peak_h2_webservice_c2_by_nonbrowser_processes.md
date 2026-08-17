# PEAK hunt H2 - Cloud services used as command and control by processes that have no business there

## Prepare

**Hypothesis.** If SHEETCORD or the HACKERAI C2 Agent is present, then a process outside our browser and developer-toolchain
baseline is talking to `sheets.googleapis.com` or the GitHub Gist endpoints, on a schedule, from a user-writable directory.
The traffic is TLS to a domain we cannot block and will not appear on any threat feed, so the anomaly is the *caller*, not the
destination.

**Why this matters.** The cluster used three different C2 transports over ten months: a custom HTTP server on port 8080, Google
Sheets API v4 with a hardcoded GCP service account, and GitHub Gists with a hardcoded personal access token. Two of the three
are indistinguishable from legitimate SaaS traffic at the network layer. Only process attribution separates them.

**Scope.** Ninety days of endpoint network telemetry with process attribution (Defender XDR `DeviceNetworkEvents`, Sysmon EID 3,
or an EDR equivalent). Proxy logs alone are not sufficient unless they carry the originating process.

**Data quality check first.** Verify that TLS connections are logged with the initiating process image path, not just the
destination. If your proxy sees the traffic but cannot name the process, this hunt cannot run in your environment as written -
pivot to the endpoint sensor or record the gap.

**Known-good baseline.** Build the allowlist before hunting: browsers, your IDEs and CLI tooling, backup and sync agents,
anything that legitimately reaches Google APIs or GitHub. Everything else, especially anything running from `AppData` or
`%TEMP%`, is a candidate.

## Execute

```kql
// Non-browser, non-toolchain processes reaching Google Sheets or GitHub Gists from user-writable paths.
let allow = dynamic(["chrome.exe","msedge.exe","firefox.exe","code.exe","git.exe","node.exe","python.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any ("sheets.googleapis.com", "gist.githubusercontent.com", "api.github.com/gists")
| where InitiatingProcessFileName !in~ (allow)
| where InitiatingProcessFolderPath has_any (@"\AppData\", @"\Temp\", @"\Users\Public\")
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Destinations = make_set(RemoteUrl, 10)
        by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| where Connections > 5
| sort by Connections desc
```

```kql
// Beacon-shaped regularity: a low standard deviation between check-ins is the tell, not the volume.
let allow = dynamic(["chrome.exe","msedge.exe","firefox.exe","code.exe","git.exe","node.exe","python.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("sheets.googleapis.com", "gist.githubusercontent.com", "api.github.com/gists")
| where InitiatingProcessFileName !in~ (allow)
| sort by DeviceId asc, InitiatingProcessFileName asc, Timestamp asc
| extend PrevTs = prev(Timestamp), PrevKey = strcat(prev(DeviceId), prev(InitiatingProcessFileName))
| where PrevKey == strcat(DeviceId, InitiatingProcessFileName)
| extend DeltaSeconds = datetime_diff('second', Timestamp, PrevTs)
| where DeltaSeconds between (10 .. 7200)
| summarize Checkins = count(), MedianInterval = percentile(DeltaSeconds, 50), IntervalStdDev = stdev(DeltaSeconds)
        by DeviceId, DeviceName, InitiatingProcessFileName
| where Checkins > 20 and IntervalStdDev < (MedianInterval * 0.25)
| sort by Checkins desc
```

```bash
# Author: Jarmi
# On a suspect host, tie the TLS session to a process without relying on the EDR.
sudo ss -tnp 2>/dev/null | grep -Ei '(googleapis|github)' || true
# Windows equivalent on the endpoint (run in an elevated PowerShell):
#   Get-NetTCPConnection -State Established |
#     ForEach-Object { [pscustomobject]@{ Remote=$_.RemoteAddress; Port=$_.RemotePort;
#       Proc=(Get-Process -Id $_.OwningProcess).Path } } | Where-Object { $_.Proc -match 'AppData|Temp|Public' }
```

## Act

**A named hit** - dump the process image, hash it, and check the binary for a Go build ID and the strings
`main.installStartupEntry` or `performJunkOperations` using the YARA rules in this folder. If the binary embeds a GCP service
account JSON or a `ghp_` token, you have the operator's credential, which is reportable to Google or GitHub for revocation and
gives the wider victim set a takedown lever.

**Beacon-shaped regularity from an allowlisted process** deserves a second look before dismissal: check whether the allowlisted
binary is running from its expected path, since the hijack pattern in this cluster is precisely about wearing a trusted name.

**No hits** - keep the query as a scheduled detection. This transport class is cheap for the actor to re-adopt, and the cluster
has already changed C2 mechanism twice.

## Knowledge

Record the allowlist you built; it is the reusable artefact, not the query. Note in the detection backlog that blocking
`sheets.googleapis.com` is not an available control in most estates, which is exactly why process attribution has to be a
funded telemetry requirement rather than a nice-to-have.
