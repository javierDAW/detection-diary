# PEAK hunt H3 - Egress: calendar-hosted payloads, look-alike domains and large chunked PUT uploads

## Prepare

**Hypothesis.** If MacSync is active, then a non-calendar process on a Mac fetches a public iCloud calendar or a calendar attachment,
later connects to a look-alike Apple domain (`apple03cloudstore.com`, `appstore.com.mx` hosts), polls `/v1/agent/ping`, and uploads
collected data with `PUT` requests of up to 90 MB per chunk. Kaspersky documents the calendar fetch, the endpoints and the chunk size.

**Why third.** Network evidence reaches hosts that were never instrumented endpoint-side and survives when the on-disk artifacts have been
cleaned (most stages delete their temporary files and logs).

**Scope.** Proxy, DNS, TLS-SNI and flow telemetry for the last 90 days, plus endpoint network events where available.

**Data quality check first.** The URL path (`/v1/...`) is only visible if you decrypt TLS or your sensor records full URLs. Without it,
rely on the domain and on request body size.

## Execute

```kql
// Defender XDR: the published domains, or a process that is not a calendar client talking to iCloud CalDAV hosts.
let domains = dynamic(["toria.app","warpcast.asia","docsend.appstore.com.mx","streamyard.appstore.com.mx","waaako.appstore.com.mx","apple03cloudstore.com"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (domains)
    or (RemoteUrl has_any ("caldav.icloud.com","gateway.icloud.com") and InitiatingProcessFileName !in~ (dynamic(["<add_known_calendar_clients>"])))
| summarize First = min(Timestamp), Connections = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| sort by First asc
```

```bash
# Author: Jarmi
# Zeek http.log: large PUT bodies, the shape of 90 MB chunked uploads. Adjust the threshold to your own baseline.
zeek-cut ts id.orig_h method host uri request_body_len < http.log | awk '$3=="PUT" && $6>=80000000'
# DNS: any lookup of the published domains.
zeek-cut ts id.orig_h query < dns.log | grep -E '(^|\.)(apple03cloudstore\.com|toria\.app|warpcast\.asia)$|(docsend|streamyard|waaako)\.appstore\.com\.mx$'
```

## Act

**A look-alike domain lookup from a Mac** is a priority finding: pull the endpoint's process list for the same minute and go to H1 and H2.
Remember the infrastructure rotates, so a miss on the published names does not clear a host; the `/v1/agent/ping` path and the
`X-Upload-Token` header survive domain changes if you can see them.

**Calendar fetches by a non-calendar process** are a lead, not a verdict. Do not block `icloud.com`; block the two exact URLs in
`iocs.csv` at the proxy if you run URL filtering, and alert on new published-calendar URLs requested by scripts.

**No hits** do not clear a host if TLS is not inspected; state the visibility gap in the report.
