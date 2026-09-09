# PEAK hunt H2 - Web layer: POST requests to webtop scripts and the 201 text/css answer

## Prepare

**Hypothesis.** If the web shell is in use, then the APM virtual server received POST requests to one of three webtop scripts whose body
starts with `BSOHAzPB`, and answered with HTTP 201 and `Content-Type: text/css; charset=utf-8`. Before that, an operator may have
fingerprinted the appliance through `/mgmt/shared/identified-devices/config/device-info`, the REST endpoint Defused reported being
targeted after the CVE-2025-53521 reclassification.

**Why.** Stock webtop pages fetch these scripts with GET to obtain styles. A POST, a 201 or a stylesheet that answers with a status other
than 200 or 304 stands out in a baseline, and it is visible without touching the appliance.

**Scope.** Reverse proxy, WAF and appliance request logs for the APM virtual servers from 2026-03-27 (reclassification and KEV addition)
onward; extend backwards if logs allow, because the exploitation start date has not been published.

**Data quality check first.** Find out whether the log source records the response status and the request method. If TLS terminates on
the appliance itself, a network tap sees nothing; use the appliance's own request log.

## Execute

```kql
// Sentinel: POSTs to the three webtop scripts and device-info reconnaissance, by source address.
CommonSecurityLog
| where TimeGenerated > datetime(2026-03-27)
| extend Url = tostring(RequestURL), Method = toupper(tostring(RequestMethod))
| where (Method == "POST" and Url has_any ("apm_css.php3","full_wt.php3","webtop_popup_css.php3"))
     or Url has "/mgmt/shared/identified-devices/config/device-info"
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Requests = count() by SourceIP, Url, Method
| sort by Requests desc
```

```bash
# Author: Jarmi
# Plain access-log export: POSTs to the webtop scripts and any 201 answered with a stylesheet script.
grep -hE '"POST [^"]*(apm_css|full_wt|webtop_popup_css)\.php3' /var/log/httpd/*access* 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
grep -hE '(apm_css|full_wt|webtop_popup_css)\.php3[^"]*" 201 ' /var/log/httpd/*access* 2>/dev/null | head -20
```

## Act

**POST traffic to a webtop script from a non-user source, or any 201 from these scripts,** is a priority finding: record the source addresses
and timestamps, then go to H1 on that appliance. Do not block the source and move on; the implant may already be installed.

**Device-info requests from the internet** show that the management REST surface is reachable. Close that exposure regardless of the
outcome, and treat the source as a scanner unless a POST to a webtop script follows from the same address.

**No hits** can mean the operator used another route or that your logs lack the data. Say which, and carry the gap into H3.
