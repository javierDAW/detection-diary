# PEAK hunt H2 - Shortened link, Cloudflare Turnstile, fake OneDrive page and Frameless BitB script paths

## Prepare

**Hypothesis.** If a user followed a TA419 link, then proxy, DNS or endpoint telemetry shows a shortened URL followed within seconds by a first-stage domain (fake OneDrive loading screen behind a Cloudflare Turnstile check),
then a second-stage domain (the adversary-in-the-middle page), and requests for `/secondary/script.js`, `/primary/script.js` and `/secondary/observe.js`. Proofpoint publishes eight first-stage and seven
second-stage domains first seen between December 2025 and July 2026, and describes the three script paths.

**Why second.** After the email stage, the redirect chain is the next place with fixed values to search for; it also gives the click time to anchor the sign-in review in H3.

**Scope.** Proxy, DNS and endpoint network logs for the last 180 days (the earliest published domain is from December 2025).

**Data quality check first.** Confirm that DNS logs include the client address and that the proxy log keeps the request path. HTTPS inspection is needed to see the script paths. Without it, use the domain lists only.

## Execute

```kql
// Defender XDR: endpoint network events for any published domain (full query with clicks in kql/k2).
let domains = dynamic(["driftshare.co","quickfly.online","cirrushare.co","goshshare.online","synchvault.co","msfile.online","winsync.cloud","sharehub.space",
  "globalfileshareplatform.com","smartsyncbox.com","mypublicshare.com","cloudsyncpulse.com","onecloudfilesync.com","publicsharefile.cloud","fileswiftonline.cloud"]);
DeviceNetworkEvents
| where Timestamp > ago(180d) and RemoteUrl has_any (domains)
| summarize First = min(Timestamp), Last = max(Timestamp), Hits = count() by DeviceName, InitiatingProcessAccountName, RemoteUrl
```

```bash
# Author: Jarmi
# Squid-style proxy log: the three kit paths on any host that is not Microsoft.
grep -E '/secondary/(script|observe)\.js|/primary/script\.js' /var/log/squid/access.log* | grep -vE 'microsoft|office\.com|live\.com' | head -50
# Zeek x509: the shared self-signed certificate subject.
zcat -f /opt/zeek/logs/*/x509.*.log.gz 2>/dev/null | zeek-cut ts id certificate.subject | grep -E 'Castro Inc.*Millsstad|Millsstad.*Castro Inc'
```

## Act

**A hit on a second-stage domain or on `observe.js`** means the user reached the relay page. Go to H3 for the account and open the page in an isolated browser to confirm. Do not infer that credentials were captured from a DNS hit alone:
the page must also have been loaded and completed by the user.

**A hit on a first-stage domain only** means the chain started. A Turnstile check can stop automated scanners and the user may have left; check the user's later sign-ins anyway.

**Matching script paths on an unlisted host** are a lead for new infrastructure. Capture the page, hash it, and run the YARA rule `TA419_BitB_Phishing_Page_Kit_Markers` against the capture. Share new domains; Proofpoint's list is dated.

**No hits** do not clear the user: the first click is on a URL shortener and the chain may use domains outside the list.
