# PEAK hunt H3 - ORB-aware access baselining and abuse of our own small devices

## Prepare

**Hypothesis.** If QTFY or a QTRouter customer operates against us, remote access activity reaches our edge from addresses that look
local or residential and that are new to the account, because the platform deliberately uses compromised IoT devices near the
victim and commercial proxy nodes. Static blocking does not work against this: Lumen's own assessment is that traffic passes through
dynamically rotating commercial proxies. The detection has to come from behaviour, not from indicators.

**Second half of the hypothesis.** Our own small devices (branch routers, cameras, NAS units, building systems) may already be
nodes in someone's relay network. Such a device accepts inbound sessions from many unrelated sources and forwards them outward,
a pattern no router, camera or NAS normally has.

**Data quality check first.** For the access half you need VPN or SSO sign-in logs with source IP and ASN for at least 90 days. For
the device half you need flow records or firewall logs for branch and IoT segments.

## Execute

```kql
// Access half 1: sign-ins from a source ASN never seen for the user in the previous 60 days (Entra ID).
let history = SigninLogs
  | where TimeGenerated between (ago(60d) .. ago(1d)) and ResultType == 0
  | summarize KnownAsns = make_set(tostring(AutonomousSystemNumber)) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| extend Asn = tostring(AutonomousSystemNumber)
| join kind=leftouter history on UserPrincipalName
| where isnull(KnownAsns) or not(set_has_element(KnownAsns, Asn))
| project TimeGenerated, UserPrincipalName, IPAddress, Asn, Location = tostring(LocationDetails.countryOrRegion), AppDisplayName, ClientAppUsed
| sort by TimeGenerated desc
```

```kql
// Access half 2: VPN or edge admin logins from addresses that also appear as scan sources against us in the last 30 days.
let scanners = CommonSecurityLog
  | where TimeGenerated > ago(30d)
  | where DeviceAction in~ ("deny","drop","blocked")
  | summarize Probes = count() by SourceIP
  | where Probes > 50;
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where Activity has_any ("login","authentication","logon") and DeviceAction in~ ("allow","accept","success")
| join kind=inner scanners on SourceIP
| project TimeGenerated, SourceIP, DestinationIP, DestinationUserName, Activity, Probes
| sort by TimeGenerated desc
```

```bash
# Author: Jarmi
# Device half: on a branch router or Linux-based device, look for listeners that match Clash defaults (mixed 7890, SOCKS 7891, controller 9090)
# and for processes named clash. These are tool defaults, not QTFY-specific values, so treat a match as a lead.
ss -ltnp 2>/dev/null | grep -E ':(7890|7891|9090)\b' ; ps w 2>/dev/null | grep -i '[c]lash'
opkg list-installed 2>/dev/null | grep -iE 'clash|v2ray|shadowsocks|trojan'
```

## Act

**A successful sign-in from a first-seen ASN that also scanned us** is a high-priority lead: expire the session, force
re-authentication with phishing-resistant MFA and review what the session touched.

**A first-seen ASN alone** is noisy (travel, mobile carriers). Use it to rank users for review, not to page.

**A device with a Clash-style listener or proxy packages it was never configured with** has been repurposed. Isolate it from the
network, image its flash if possible, and treat the credentials it stored as exposed. Re-flashing from a vendor image is the
recovery path; an in-place clean-up of a compromised embedded device is not reliable.

## Knowledge

Keep the per-user ASN baseline as a standing detection input and keep an inventory of every device class that can run custom firmware.
Record which small devices cannot be monitored at all; those are the blind spots an ORB operator will choose.
