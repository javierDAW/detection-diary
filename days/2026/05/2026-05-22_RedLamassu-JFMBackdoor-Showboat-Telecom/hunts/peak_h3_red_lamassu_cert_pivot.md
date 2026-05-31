# PEAK H3 — Red Lamassu shared X.509 fingerprint pivot for primary cluster discovery

**Date:** 2026-05-22
**Author:** Jarmi
**Hypothesis class:** Infrastructure tracking (PEAK)
**Confidence:** medium

## Hypothesis

Any TLS connection from our environment to an internet host that serves the
self-signed `O=My Organization` certificate with SHA256 fingerprint
`27df475626aafce2ea1548a9f35efb9ad951298c8b11a6adb3ccdfcd5170c677`, or any
Cloudflare-origin certificate for `*.namefuture[.]site` (serial
722215547421393549906800483143167899186483629093) or `*.newsprojects[.]online`
(serial 604003291824433169701962900588762674473924908065), indicates contact
with Red Lamassu primary-cluster infrastructure. Lumen and PwC observed
these fingerprints across at least 20 C2 nodes spanning 2023-2026.

## Why this discriminates

- The `O=My Organization` subject is a generated default used across the
  whole primary cluster — the chance of a benign host serving the same
  SHA256 fingerprint is effectively zero.
- Cloudflare origin certificates carry serial numbers that uniquely identify
  the origin host; the two Red Lamassu serials are stable anchors that
  survive front-end IP rotation.
- The cluster includes two impersonating telecom domains (`kaztelecom.shop`,
  `singtelcom.site`) and one dynamic-DNS host (`telecom.webredirect.org`) —
  combining the fingerprint with a TLS SNI match elevates confidence to high.

## Expected benign vs malicious

- Benign: zero for the exact `My Organization` fingerprint. The Cloudflare
  origin certs may surface against unrelated Cloudflare-fronted sites that
  share the same `*.<domain>` SAN — anchor on the serial number to avoid
  Cloudflare collisions.
- Malicious: any egress to the IPs that served those certificates (full list
  in Table 3 of the PwC blog and Figure 7-8 of the Lumen blog) during the
  observation window of that IP — record both `First observed` and
  `Last observed` to scope hunts properly.

## Action on match

1. Block the matching IP and the matching SNI at the egress proxy.
2. Hunt netflow back 6 months for the same IP-port pair; Red Lamassu often
   moves victim traffic to port 53 to bypass perimeter security devices.
3. If the host is an edge appliance (router, Outlook server, mail gateway),
   acquire a forensic image — Showboat persistence is service-based and the
   primary install path is on Linux-based infrastructure devices.
4. Cross-reference DNS queries from the same source over the prior 7 days
   for the eight published Red Lamassu C2 hostnames.

## Linked rules

- `kql/red_lamassu_c2_egress_telecom_themed_domains.kql`
- `suricata/red_lamassu_2026_05.rules` (sid 8220010 for the X.509 fingerprint)
- `yara/RedLamassu_JFMBackdoor_Showboat_2026.yar` (for any captured binary
  pulled during the hunt)
