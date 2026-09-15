# PEAK hunt H1 - Egress: Telegram Bot API and object storage from binaries that should not use them

## Prepare

**Hypothesis.** If CHOSEN BRICK (FBI: HEAVYGRAM) is on a host, then an executable under `C:\ProgramData` talks to `api.telegram.org`
(command and control, one bot per victim) and to Vultr Object Storage or StorjShare (exfiltration). The advisory lists
`api.telegram.org`, `backblazeb2.com`, `vultrobjects.com`, `storjshare.io`, `iproyal.com` and `lightningproxies.net`, and states that
they are legitimate services: the signal is which process talks to them, not the destination.

**Why first.** The implant needs a path to the operator and a path to move data out. Its on-disk names and folders can change; the
Telegram API calls (`getUpdates`, `sendDocument`, `sendPhoto`, `getFile`) are the part its design cannot drop.

**Scope.** Endpoint network telemetry and proxy logs for the last 90 days, focused on staff and contractors who are journalists,
activists, researchers or diaspora community members, and on any managed device they use. For individuals on personal devices
the data does not exist in your estate; use H3.

**Data quality check first.** Confirm your telemetry records the initiating process path, not only the destination. Without it this
hunt reduces to counting Telegram users.

## Execute

```kql
// Defender XDR: ProgramData binaries talking to Telegram, object storage or the proxy services named in the advisory.
let services = dynamic(["api.telegram.org","vultrobjects.com","storjshare.io","backblazeb2.com","iproyal.com","lightningproxies.net"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (services)
| where InitiatingProcessFolderPath startswith @"C:\ProgramData\"
| summarize First = min(Timestamp), Last = max(Timestamp), Connections = count(), Dest = make_set(RemoteUrl, 8)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| sort by Connections desc
```

```bash
# Author: Jarmi
# Proxy export (squid-style): clients that requested a Telegram bot path; bot identifiers are per victim, so a value seen on one host
# will not appear on another.
grep -hE 'api\.telegram\.org/bot[0-9]+:' /var/log/squid/access.log* 2>/dev/null | awk '{print $3}' | sort | uniq -c | sort -rn | head -30
```

## Act

**A ProgramData binary that polls the Telegram Bot API** is a priority finding: isolate the host from the network but keep it powered,
capture memory and the binary, and check H2 on the same host. Do not block `api.telegram.org` estate-wide on the strength of this
hunt; ordinary users run Telegram.

**Object-storage traffic from an unsigned binary** is a second-tier lead; look at the bucket name. The FBI lists
`micbucket.ams1.vultrobjects.com` (tool staging, `MSCache.exe` and `credentials.json`) as actor-specific.

**No hits** do not clear individuals who work on personal devices. Say so in the report and move to H3.
