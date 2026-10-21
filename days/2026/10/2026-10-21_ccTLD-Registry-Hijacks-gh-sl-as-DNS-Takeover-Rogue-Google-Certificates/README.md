---
date: 2026-10-21
title: "ccTLD registry hijacks on .gh, .sl and .as: authoritative DNS takeover and domain-validated certificates for Google names"
clusters: ["Unattributed ccTLD registry hijack operator (Google disclosure 2026-10-06)"]
cluster_country: "Unknown"
techniques_enterprise: [T1584.001, T1584.002, T1588.004, T1608.003]
techniques_ics: []
platforms: [cloud-multi]
sectors: [technology, internet-infrastructure]
category: other
---

# ccTLD registry hijacks on .gh, .sl and .as: authoritative DNS takeover and domain-validated certificates for Google names

## TL;DR

Google's Chrome Secure Web and Networking Team disclosed on 2026-10-06 that attackers compromised third-party registry operators for the country-code TLDs .gh (Ghana), .sl (Sierra Leone) and .as (American Samoa), changed authoritative DNS records and obtained unauthorized HTTPS certificates for several Google domains and for other organisations. Press analysis of Certificate Transparency (CT) data dates the certificates to 2026-09-22 (.gh), 2026-09-25 (.sl) and 2026-09-27 (.as), with most of each batch issued within about 90 minutes; the count is disputed (at least 12 for Google and YouTube names per The Hacker News, 32 across brands per iTnews). No actor, nameserver, IP address, registry operator, entry method or CVE has been published, and nobody has shown that traffic was intercepted. The case matters today because the weakest link was not a server but the trust chain around a domain: whoever controls the zone the CA reads can pass domain validation, and a restrictive CAA record does not stop that while the hijack is live.

## Attribution and confidence

| Field | Value |
|---|---|
| Cluster | Unattributed; no alias, no country nexus published |
| Discovery | Google (aware "last week" before its 2026-10-06 post); Chrome blocked the certificates with CRLSets and worked with CAs on revocation |
| Vendors and dates | Google Chrome blog 2026-10-06; BleepingComputer and The Register 2026-10-07; The Hacker News 2026-10; iTnews 2026-10-08 (via CircleID) |
| Motivation | Not stated; the capability (valid certificates for Google names) fits traffic interception or phishing, but no source shows use |
| Confidence | **low** for any attribution (none exists). **High** that the registry-level hijacks and the unauthorized certificates happened (Google primary statement). **Medium** for dates, counts and issuers, which come from press reading of CT logs |

| Overlap | Relation |
|---|---|
| Repo case 2026-06-03 (ip6.arpa reverse DNS phishing) | Same slot (#29 DNS abuse), different mechanism: abuse of a legitimate DNS zone for phishing delivery, no certificate issuance |
| Repo case 2026-06-24 (SRG / Luna Moth fast flux) | Last primary in this slot, 119 days ago; fast flux hosting by an e-crime crew, unrelated to registry compromise |
| Repo case 2026-10-19 (BeyondTrust zero-day) and 2026-10-15 (AhsayCBS) | No link in any source read |

Anti-duplicate check: `grep -rliE 'ccTLD|\.com\.gh|registry hijack' days/ byActor/` before publishing found no earlier case.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Registry compromise | T1584.001, T1584.002 (inferred) | Third-party operators of .gh, .sl and .as compromised; method and operators not published. A vendor blog (Security Arsenal) suggests admin panels or EPP infrastructure, which is inference |
| DNS change | T1584.001, T1584.002 | Authoritative records changed so the target names resolve to infrastructure the actor controls |
| Certificate issuance | T1588.004, T1608.003 | A public CA validates control through the attacker's DNS and issues a DV certificate; reported issuers are Let's Encrypt, ZeroSSL and, in one iTnews finding, Cloudflare's CA |
| CT logging | n/a | Certificates appear in CT on 2026-09-22 (.gh), 2026-09-25 (.sl), 2026-09-27 (.as) |
| Use of the certificates | not established | A valid certificate on an attacker-controlled IP address would give a convincing page or an interception position; no source reports it |
| Detection and response | n/a | Chrome CRLSet block, CA revocations (3 certificates on 2026-09-26, 9 on 2026-10-01 for the 12 in the THN count), CT review for other brands |
| Residual risk | n/a | Cached domain control validation, non-Chrome clients, CAA that cannot stop an active hijack |

![ccTLD registry hijacks kill chain](./kill_chain.svg)

The left lane follows the trust chain from the registry to the client; red stages (1 to 3 and 7) are the points where a defender's control matters most: registry security, the CA's view of DNS, and the period after restoration. The right lane records what is public and what is not, the seven hostnames, the source conflicts and the detection and hardening anchors. The detection anchors are CT issuance, delegation and CAA drift, the exposure window of 2026-09-22 to 2026-10-01 and a non-Google issuer on a Google-brand name.

## Stage-by-stage detail

### Stage 1: registry operators compromised

Google says the compromise was at the third-party ccTLD registry level and that its own systems were not involved. The sources do not name the operators, the entry method or the actor. Security Arsenal describes registry admin panels or EPP infrastructure as the likely path; that is the vendor's reasoning, not a published finding. iTnews contacted the operators of .gh, .as and the Sierra Leone TLD and received no response. Techniques: T1584.001 (Compromise Infrastructure: Domains) and T1584.002 (DNS Server), the latter by inference.

### Stage 2: authoritative DNS changed

The attackers modified authoritative DNS records so that names under the three ccTLDs pointed at infrastructure they controlled (BleepingComputer). Google said any domain under the three TLDs was potentially at risk. The registry-level dates and durations of the hijacks are not published; the only hard timestamps are the CT entries.

```text
Names named in reporting (legitimate Google properties):
.gh  google.com.gh  youtube.com.gh
.sl  google.sl  google.com.sl  youtube.sl
.as  google.as  youtube.as
```

### Stage 3: validation and issuance

A CA proves domain control by asking for a DNS record (BleepingComputer gives the usual TXT example) or another accepted method; because the attacker controlled the authoritative answers, the checks passed. The issuing CAs were not named by Google, which has "no reason to believe" they erred. The Hacker News reports that 11 of the 12 certificates in its count came from Let's Encrypt and 1 from ZeroSSL, all domain-validated; iTnews reports free wildcard certificates from Let's Encrypt and ZeroSSL and one certificate from Cloudflare's CA for a domain of another major technology brand, and speculates that this may point to the actor's account, which is unconfirmed. Techniques: T1588.004 (Obtain Capabilities: Digital Certificates) and T1608.003 (Stage Capabilities: Install Digital Certificate).

```text
Issuance dates in CT (per THN and iTnews):
.gh  2026-09-22
.sl  2026-09-25
.as  2026-09-27     most certificates per ccTLD within about 90 minutes
```

### Stage 4: Certificate Transparency

CT is how the story became visible. The Hacker News lists 12 certificates for seven Google and YouTube names; iTnews counts 32 across brands by comparing public CT logs with Chrome's blocklist and says the count has not been independently reproduced. Both can be right if the 12 are the Google and YouTube subset. Treat both numbers as press readings.

### Stage 5: use of the certificates (not established)

A valid certificate on an attacker-controlled IP address can serve a convincing page or sit in the middle of a connection. None of the sources reports interception or abuse, and the dev.to commentary states that the dates, duration and validation method are not established. The exposure window for clients is the span from the first logged certificate (2026-09-22) to the last revocation in the THN set (2026-10-01).

### Stage 6: detection and response

Google learned of the hijacks the week before its post. It first blocked certificates for its own properties in Chrome with CRLSets, worked with CAs on revocation (which also helps non-Chrome clients), then used CT to find other affected organisations, "several leading global brands and widely used online services" in its words, and contacted them where possible. THN gives the revocation timing: two .gh certificates and the ZeroSSL certificate on 2026-09-26, the other nine on 2026-10-01. Google warns it cannot guarantee it found every affected domain.

### Stage 7: residual risk after restoration

Google recommends monitoring CT for the whole portfolio including parked and regional ccTLD names, and publishing restrictive CAA records (RFC 8659) that name your CA and, where supported, your ACME account and validation methods (RFC 8657). CAA cannot stop issuance during an active hijack, because it is itself a DNS record that the attacker controls; its value is to block reuse of cached validation once control returns. THN reports Baseline Requirements allow reuse of validation for up to 200 days (100 from March 2027, 10 from March 2029) and that Let's Encrypt reuses checks for 30 days. The same article found strict CAA records naming only `pki.goog` on all seven Google names on 2026-10-07, which is consistent with a policy that was in place or restored and which, per Google, would not by itself have stopped issuance during the hijack.

## Detection strategy

There is no sample, no exploit, no implant and no network protocol to fingerprint. The takeover happened at registries and CAs, outside any victim network. Detection therefore rests on three things: public CT evidence for names you own, delegation and CAA state checked from outside, and exposure scoping for the names your users reached during the window. The endpoint and network rules in this folder are exposure and consistency checks, not attack signatures, and are marked low confidence.

### Telemetry that matters

- Certificate Transparency logs through crt.sh, CertSpotter or Google's CT search, for every inventoried domain.
- Registrar and registry records (RDAP, whois, registrar audit logs) for NS, DS and contact changes.
- Authoritative and recursive DNS logs: Sentinel `DnsEvents`, Windows DNS Server analytic logs, resolver query logs.
- Defender XDR `DeviceNetworkEvents` (RemoteUrl, RemoteIP) and Sysmon Event ID 22 (DNS query) and 3 (network connection).
- Proxy and Zeek or Suricata TLS metadata: SNI, certificate issuer and SAN (certificate fields are visible only in TLS 1.2 or earlier, or with decryption).
- Windows DNS Server audit events and process creation for `dnscmd` and the DnsServer cmdlets on your own zones.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [sigma/01_cctld_hijack_dns_query_google_names_under_gh_sl_as.yml](./sigma/01_cctld_hijack_dns_query_google_names_under_gh_sl_as.yml) | DNS query for the seven named hostnames; exposure scoping |
| Sigma | [sigma/02_cctld_hijack_network_connection_google_names_under_gh_sl_as.yml](./sigma/02_cctld_hijack_network_connection_google_names_under_gh_sl_as.yml) | Connection whose destination hostname is one of the seven names |
| Sigma | [sigma/03_cctld_hijack_dnscmd_or_powershell_ns_caa_record_change.yml](./sigma/03_cctld_hijack_dnscmd_or_powershell_ns_caa_record_change.yml) | NS or CAA record change on your own Windows DNS Server |
| Sigma | [sigma/04_cctld_hijack_acme_client_wildcard_issuance_from_endpoint.yml](./sigma/04_cctld_hijack_acme_client_wildcard_issuance_from_endpoint.yml) | ACME client with a wildcard or DNS challenge on an unapproved host |
| KQL | [kql/k1_connections_to_hijacked_cctld_google_names_exposure_window.kql](./kql/k1_connections_to_hijacked_cctld_google_names_exposure_window.kql) | Endpoints that reached the seven names between 2026-09-22 and 2026-10-01 |
| KQL | [kql/k2_remote_ip_drift_for_watched_domains_against_30_day_baseline.kql](./kql/k2_remote_ip_drift_for_watched_domains_against_30_day_baseline.kql) | Remote IP addresses for watched domains not seen in the previous 30 days |
| KQL | [kql/k3_dns_a_and_ns_answers_changed_for_watched_domains.kql](./kql/k3_dns_a_and_ns_answers_changed_for_watched_domains.kql) | A, AAAA and NS answers that differ from the 30-day baseline (Sentinel) |
| YARA | [yara/cctld_hijack_google_names_in_logs_and_certificate_dumps.yar](./yara/cctld_hijack_google_names_in_logs_and_certificate_dumps.yar) | Two rules: the seven hostnames in text artefacts; a certificate dump with those SANs and a Let's Encrypt or ZeroSSL issuer (no sample exists) |
| Suricata | [suricata/cctld_hijack_google_names.rules](./suricata/cctld_hijack_google_names.rules) | Six rules, sids 6370001 to 6370006: DNS and SNI scoping, non-Google issuer on Google-brand names |

No rule detects the registry compromise, the DNS change at the registry or the issuance. The Suricata issuer rules are blind to TLS 1.3 without decryption, and a TLS inspection proxy will trigger them until its CA is allow-listed. Vendor-published detections for this event (Security Arsenal) were read but not reused: the page itself shows unverified field names and an unused variable.

### Threat hunting hypotheses

- **H1.** A certificate was issued for a domain in our portfolio, including parked and regional ccTLD names, by an issuer or ACME account we do not use: [hunts/peak_h1_unexpected_certificate_issuance_for_domain_portfolio.md](./hunts/peak_h1_unexpected_certificate_issuance_for_domain_portfolio.md).
- **H2.** The NS set at the registry, the authoritative answers or the CAA policy of a domain differ from the recorded baseline: [hunts/peak_h2_authoritative_dns_delegation_and_caa_drift.md](./hunts/peak_h2_authoritative_dns_delegation_and_caa_drift.md).
- **H3.** Users or applications reached the hijacked Google names between 2026-09-22 and 2026-10-01 and were served a certificate that Google did not issue: [hunts/peak_h3_client_exposure_window_review_2026_09_22_to_2026_10_01.md](./hunts/peak_h3_client_exposure_window_review_2026_09_22_to_2026_10_01.md).

## Incident response playbook

The playbook has two audiences: the owner of a domain under a ccTLD (or any domain) that may have been hijacked, and an organisation whose users may have reached one of the hijacked Google names.

### First 60 minutes (triage)

1. Inventory every domain you own from registrar and registry exports, including parked, regional and retired campaign domains; mark those under .gh, .sl and .as.
2. Search CT for each domain over the last 60 days and list every certificate with its issuer and logged time (hunt H1).
3. Compare each domain's NS set at the registry with your baseline and query every authoritative server directly for A and CAA (hunt H2).
4. If anything differs, call the registrar and the registry on a number from the contract, freeze changes on the account, and rotate the registrar and DNS-provider credentials and API keys from a clean device.
5. For each unexpected certificate, file a Certificate Problem Report with the issuing CA, quote the CT entry and ask for revocation; keep the CA's reply.
6. Pull DNS, proxy and EDR logs for 2026-09-22 to 2026-10-02 and list who reached the seven named hostnames (hunt H3).
7. Brief the helpdesk: do not tell users to click through certificate warnings, and ask them to report any warning for a Google or a company domain.
8. Do not rely on Chrome's block alone: list non-browser clients, mobile apps and embedded devices that use the affected names.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| CT entries for your domains | crt.sh JSON, CertSpotter feed | curl, python | Issuer, SAN and logged time of each certificate |
| Registrar and registry records | RDAP, whois, registrar audit log | rdap, whois, registrar export | NS, DS and contact change history |
| Authoritative answers | NS, A, AAAA, CAA from each server | dig +trace, dig @ns | Compare with the recorded baseline |
| DNS logs | Windows DNS analytic log, resolver logs, Sentinel `DnsEvents` | Export, KQL | Which clients were told which addresses in the window |
| Proxy and TLS metadata | Proxy logs, Zeek `x509.log` and `ssl.log` | zeek-cut, KQL | Issuer, SAN and destination IP address per connection |
| Endpoint network events | Defender `DeviceNetworkEvents`, Sysmon 3 and 22 | KQL, EvtxECmd | Process, user and destination for each connection |
| CA correspondence | Problem report, revocation notice | Mail export | Evidence for the timeline and for notification duties |

### IR queries and commands

```bash
# Author: Jarmi
# Show who the registry says is authoritative, then ask every listed server for A and CAA, from a machine outside the corporate resolver.
D=example.gh
dig +trace +nodnssec NS $D | tail -n 8
for NS in $(dig +short NS $D); do echo "== $NS"; dig +short @"$NS" A $D; dig +short @"$NS" CAA $D; done
```

```bash
# Author: Jarmi
# Inspect the certificate a host actually presents for a hijacked-name SNI and print issuer, dates and SAN (read-only; no data is sent beyond the handshake).
echo | openssl s_client -connect google.com.gh:443 -servername google.com.gh 2>/dev/null | openssl x509 -noout -issuer -dates -ext subjectAltName
```

```powershell
# Author: Jarmi
# Windows DNS Server: list NS and CAA records of a zone you manage and show when the zone was last changed.
Get-DnsServerResourceRecord -ZoneName "example.com" -RRType NS,CAA | Select-Object HostName, RecordType, @{n='Data';e={$_.RecordData | Out-String}}, Timestamp
```

```kql
// Author: Jarmi
// Sentinel: which clients were given an address for a watched domain that is new in the last 7 days. Replace the placeholder.
DnsEvents
| where TimeGenerated > ago(7d) and Name has "<add_known_brand_domain_1>" and QueryType == "A"
| summarize Clients = dcount(ClientIP), FirstSeen = min(TimeGenerated) by Name, IPAddresses
| sort by FirstSeen asc
```

### Containment, eradication, recovery

Exit criteria: the delegation at the registry matches the baseline and the registry or registrar account is locked with new credentials and phishing-resistant MFA; every certificate issued during the hijack is revoked and the CA has confirmed it; the CAA policy names your CA and, where the CA honours it, your ACME account and validation method; DNSSEC and registry lock are enabled where the registry offers them; and the exposure review for users and applications is closed with named owners.

What not to do: do not assume a restored zone ends the exposure, because cached domain validation can allow issuance after control returns (30 days at Let's Encrypt, up to 200 days under the Baseline Requirements per THN); do not rely on a CAA line alone, since it cannot block issuance while the attacker controls the zone; do not tell users to bypass certificate warnings; do not block the seven Google hostnames at the proxy as if they were attacker infrastructure, which would also break the real sites.

### Recovery validation

- Re-run the CT search (hunt H1) daily for 30 days after restoration, and again at day 100 and day 200 for domains where validation reuse is long.
- Re-run delegation and CAA checks (hunt H2) from at least three networks and confirm the registry lock is active.
- Confirm that no host in the exposure review still holds a session or credential created against a hijacked name.

## IOCs

This case has no network indicator. The seven hostnames below are legitimate Google properties named in reporting; they are listed for exposure scoping and are stored as `string`, not `domain`, so that the repo's blocklist feed does not blocklist Google. Full list, 20 rows: [iocs.csv](./iocs.csv). No SHA-256 or other hash exists because there is no sample.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| string | google.com.gh | .gh name with an unauthorized certificate, first logged about 2026-09-22; not malicious infrastructure | medium | The Hacker News |
| string | youtube.com.gh | Same ccTLD and date | medium | The Hacker News |
| string | google.sl | .sl name, certificates logged about 2026-09-25 | medium | The Hacker News |
| string | google.com.sl | Same ccTLD and date | medium | The Hacker News |
| string | youtube.sl | Same ccTLD and date | medium | The Hacker News |
| string | google.as | .as name, certificates logged about 2026-09-27 | medium | The Hacker News |
| string | youtube.as | Same ccTLD and date | medium | The Hacker News |
| string | Let's Encrypt | Issuer of 11 of the 12 certificates in the THN count; wildcards per iTnews | medium | The Hacker News, iTnews |
| string | ZeroSSL | Issuer of 1 of the 12 certificates in the THN count | medium | The Hacker News, iTnews |
| string | pki.goog | CAA value on all seven names on 2026-10-07; expected issuer for Google properties | medium | The Hacker News |
| note | Window 2026-09-22 to 2026-10-01 | First logged certificate to last revocation in the THN set | medium | THN, iTnews |
| note | Certificate count: at least 12 (THN) versus 32 (iTnews) | Scope differs; neither reproduced | medium | THN, iTnews |
| note | No actor, nameservers, IP addresses, registry operators or entry method published | Repo holds no network IOC for this case | high | Google, BleepingComputer |

KEV: not applicable. The sources report an operational compromise of registries and CAs' validation inputs, not a software vulnerability, and no CVE is named (Security Arsenal states the same), so `kev.md` is not generated for this case.

## Secondary findings

- **eMudhra intermediate CA keys (Google blog, 2026-10-20).** A researcher reported that private keys for eight (the post also says six) eMudhra subordinate CA certificates were generated with insufficient randomness. The report arrived on 2026-10-17 at 18:05 UTC and Chrome's CRLSet block landed at 19:45 UTC that day. Android got an equivalent update on 2026-10-19, and removal of emSign ECC Root CA - G3 from the Chrome Root Store is expected on 2026-10-27. No certificates chaining to these intermediates had been logged in CT, so none could be used against CT-enforcing clients. Not the same incident; same lesson about trusting the chain.
- **Validation reuse is the long tail.** THN reports Baseline Requirements allow reuse of domain validation for up to 200 days, falling to 100 days in March 2027 and 10 days in March 2029, while Let's Encrypt reuses checks for 30 days and plans 7 hours by 2028. Google points to CA/Browser Forum ballot SC-081v3 and the Chrome Root Program for shorter lifetimes. For a defender this sets how long to keep watching after a hijack.
- **Vendor-generated detections need testing.** Security Arsenal's blog for this event ships Sigma, KQL and VQL, but its own text flags suffix matches that also hit `.asia` and hand-picked Google netblocks, plus field names that depend on the log source. The rules in this folder avoid netblock lists and say what they cannot see.

## Pedagogical anchors

- A certificate is only as strong as the DNS a CA reads. Whoever answers for your zone, at any layer from registry to resolver, can pass domain validation; treat the registrar and registry account as tier-0.
- CAA is a record in the same zone. It limits what happens after control returns (cached validation, other CAs) but cannot stop issuance during a live hijack; pair it with registry lock, DNSSEC and CT monitoring.
- CT is your free, public audit log. Monitor every domain in the portfolio, including parked and regional ccTLD names that nobody visits; the 90-minute issuance window means daily checks are too slow for high-value names.
- Browser-side revocation (CRLSets) protects Chrome users, not apps, APIs or other browsers; exposure scoping must include non-browser clients.
- When the sources disagree on counts (12 versus 32) or give no actor, record the conflict and the gap instead of filling it; a blank IOC table is a finding.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram (Template A). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | 20 rows: the seven named hostnames (exposure scoping), issuers, dates and analyst notes; no network IOC. | [iocs.csv](./iocs.csv) |
| sigma/ | Four Sigma rules for exposure scoping, own-zone NS or CAA changes and unapproved ACME use. | [sigma/](./sigma/) |
| kql/ | Three KQL queries for the exposure window, IP drift and DNS answer drift. | [kql/](./kql/) |
| yara/cctld_hijack_google_names_in_logs_and_certificate_dumps.yar | Two YARA rules for the named hostnames in text artefacts and certificate dumps (no sample exists). | [yara/cctld_hijack_google_names_in_logs_and_certificate_dumps.yar](./yara/cctld_hijack_google_names_in_logs_and_certificate_dumps.yar) |
| suricata/cctld_hijack_google_names.rules | Six Suricata rules, sids 6370001 to 6370006. | [suricata/cctld_hijack_google_names.rules](./suricata/cctld_hijack_google_names.rules) |
| hunts/ | Three PEAK hunts (H1 to H3). | [hunts/](./hunts/) |

## Sources

- [Chrome's Response to Recent ccTLD Registry Hijacks — Google, 2026-10-06](https://blog.google/security/chromes-response-to-recent-cctld-registry-hijacks/)
- [Hackers hijack Google domains after breaching ccTLD registries — BleepingComputer, 2026-10-07](https://www.bleepingcomputer.com/news/security/hackers-hijack-google-domains-after-breaching-cctld-registries/)
- [Attackers Hijack .gh, .sl, and .as Registries to Obtain Certificates for Google Domains — The Hacker News, 2026-10](https://thehackernews.com/2026/10/attackers-hijack-gh-sl-and-as.html)
- [Attackers hijacked top-level domains, minted fake security certs for Google and other orgs — The Register, 2026-10-07](https://www.theregister.com/security/2026/10/07/attackers-hijacked-top-level-domains-minted-fake-security-certs-for-google-and-other-orgs/5301718)
- [Attackers hijack ccTLDs to fake certs for Google — iTnews, 2026-10-08](https://www.itnews.com.au/news/attackers-hijack-cctlds-to-fake-certs-for-google-629504)
- [DNS Hijacks Across Three ccTLDs Linked to 32 Unauthorized HTTPS Certificates — CircleID](https://circleid.com/posts/dns-hijacks-across-three-cctlds-linked-to-32-unauthorized-https-certificates)
- [A ccTLD Hijack Turns Authoritative DNS Into Certificate Evidence — DEV Community (commentary)](https://dev.to/ntctech/a-cctld-hijack-turns-authoritative-dns-into-certificate-evidence-561p)
- [ccTLD Registry Breach: DNS and Certificate Defense Guide — Security Arsenal (vendor analysis)](https://securityarsenal.com/blog/cctld-registry-breach-hackers-hijack-google-domains-in-ghana-american-samoa-and-sierra-leone-dns-and-certificate-defense-guide)
- [Protecting Chrome and Android Users from Compromised eMudhra Intermediate CA Certificates — Google, 2026-10-20](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)

The sources were read through automated page summaries, not in a browser. The Hacker News and iTnews figures (12 and 32 certificates, issuers, dates) derive from CT analysis that Google's own post does not repeat; check them against crt.sh or another CT search before using any of them in a report or a revocation request.
