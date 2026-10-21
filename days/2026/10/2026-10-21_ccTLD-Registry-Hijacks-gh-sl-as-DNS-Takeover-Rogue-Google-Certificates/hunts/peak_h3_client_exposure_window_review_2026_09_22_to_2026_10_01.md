# PEAK hunt H3 - Client exposure review for the .gh, .sl and .as hijack window (2026-09-22 to 2026-10-01)

## Prepare

**Hypothesis.** If any user or system reached google.com.gh, youtube.com.gh, google.sl, google.com.sl, youtube.sl, google.as or youtube.as between the first logged certificate (2026-09-22) and the last revocation (2026-10-01), the connection may have been served by attacker infrastructure with a valid certificate. Nobody has shown that traffic was intercepted; the exposure review answers who could have been affected.

**Why third.** H1 and H2 protect your own domains. H3 protects your users and applications when somebody else's domain was hijacked, which is the position most organisations were in.

**Scope.** DNS resolver logs, proxy logs, EDR network telemetry and (where available) Zeek or Suricata TLS metadata for 2026-09-22 to 2026-10-02, for the seven names above and any other name under .gh, .sl or .as that your organisation depends on.

**Data quality check first.** Confirm log retention reaches 2026-09-22, and that DNS or proxy logs keep the answer IP address and, ideally, the certificate issuer.

## Execute

```kql
// Full query in kql/k1. Endpoints that reached the named hostnames in the window.
DeviceNetworkEvents
| where Timestamp between (datetime(2026-09-22) .. datetime(2026-10-02))
| where RemoteUrl has_any (dynamic(["google.com.gh", "youtube.com.gh", "google.sl", "google.com.sl", "youtube.sl", "google.as", "youtube.as"]))
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, RemoteUrl
```

```bash
# Author: Jarmi
# Zeek x509.log: list certificates whose SAN contains the hijacked names and print issuer and validity (log paths and field order depend on your Zeek version).
zcat logs/2026-09-2*/x509.*.log.gz logs/2026-10-0*/x509.*.log.gz 2>/dev/null \
 | zeek-cut ts certificate.issuer san.dns \
 | grep -Ei 'google\.com\.gh|youtube\.com\.gh|google\.sl|google\.com\.sl|youtube\.sl|google\.as|youtube\.as' | sort -u
```

## Act

1. For each hit, compare the destination IP address with the addresses that the Google names resolve to today and in the days before 2026-09-22; an address outside Google's published ranges in the window is the lead.
2. If the issuer was not Google Trust Services, treat the session as potentially intercepted: list the accounts and applications involved and reset credentials that were typed into pages under those names.
3. Remember that Chrome blocked the certificates through CRLSets; other browsers and non-browser clients (mobile apps, API clients, Electron apps) may not have.
4. Ask Google Workspace administrators whether any of those domains sit in a trust or SSO configuration of your tenant.

## Knowledge

- The sources do not establish hijack dates at the registry, the duration of each hijack, or whether traffic was intercepted; the certificate dates are the only hard timestamps.
- Most users never visit these ccTLD names; the realistic exposure is automation, hard-coded URLs and regional users.
- Record the result per source system, including the negative ones, so the next incident does not start from scratch.
