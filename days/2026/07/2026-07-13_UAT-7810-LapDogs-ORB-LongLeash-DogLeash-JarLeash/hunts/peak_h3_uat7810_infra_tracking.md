# PEAK Hunt H3 — Tracking UAT-7810 ORB infrastructure (CTI tradecraft)

**Hypothesis.** UAT-7810 continually stands up new VPS download/relay servers and new compromised relay nodes; the durable pivots are the self-signed TLS cert identity (subject `CN=exploit`, `O=exploit`, ...), the port-99 TLS relay pattern, and the payload-staging ports 8088/2222 — not the IP addresses, which rotate.

**Prepare.** Data sources: internet-wide scan data (Censys/Shodan/FOFA), certificate transparency + TLS scan corpora, passive DNS, and your own egress logs. Fields: TLS `cert_subject`/`cert_issuer` and cert SHA256 fingerprint, open-port banners on 99/8088/2222, ASN/hosting provider, JARM/JA4S where available.

**Execute.**
1. Pivot on the cert subject `C=exploit, ST=exploit, L=exploit, O=exploit, OU=exploit, CN=exploit` and the known cert fingerprint `c2ab9adaba93ff094b8f3fc37d906014d870582039d276b7bd03e6fd583d8a15` across TLS scan data to surface additional servers hosting a port-99 TLS service.
2. Query scan data for hosts exposing TLS on TCP/99 together with HTTP staging on 8088/2222 — that co-occurrence is an ORB-server tell.
3. Cluster candidate IPs by hosting provider/ASN and by the multi-arch payload set they serve (MIPS/ARM/x64 DOGLEASH); watch for reuse of an IP across both Ruckus and ASUS AiCloud (CVE-2025-2492) exploitation, as seen with 217.15.164.147.
4. Feed confirmed live infra to blocking with a short TTL and to the detection team; re-validate weekly because ORB infra decays.

**Act.** Publish fresh infra internally with a decay note, correlate any hit against H1/H2 host findings, and share cert/JA4 pivots with the wider CTI community. Attribute infrastructure to UAT-7810 tooling, but remember ORB nodes are used by SECONDARY actors — a relay hit does not by itself attribute the downstream operation.

**Notes.** The cert DN and port topology are the resilient selectors; treat the four documented IPs as expiring leads, not permanent indicators.
