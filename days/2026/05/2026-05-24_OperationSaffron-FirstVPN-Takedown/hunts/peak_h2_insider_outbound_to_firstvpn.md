# PEAK H2 — Insider or contractor reaching First VPN from inside the corporate network

## Hypothesis
A current or former employee, contractor, or compromised endpoint in our corporate network attempted to connect outbound to First VPN Service customer-facing infrastructure (1vpns.com, 1vpns.net, 1vpns.org, 1jabber.com, or any current/historical exit-node IP) during the activity window 2024-2026. The motivation may be benign curiosity, deliberate operational-security for unauthorized data egress, or a compromised endpoint using the service as an unattributed C2 channel.

## Why this discriminates
A legitimate user has no business reason to reach a service marketed exclusively on Russian-language carding forums (`Exploit[.]in`, `XSS[.]is`) and priced for short-burst anonymization at $2/day. The customer-facing surface — web, Jabber, Telegram — is narrow and now sinkholed; any reachout from inside our perimeter is itself anomalous. The exit-node IPs are less narrow but the **combined** signal (DNS lookup + TLS to seized domain + subsequent traffic to exit-node IP) is the discriminator.

## Expected benign vs malicious
- Benign: SOC analyst manually validating an IOC by performing a deliberate test connection from a workstation. Threat-intel pipeline (recorded-future, VirusTotal) auto-pivoting to seized infrastructure as part of enrichment. Whitelist these origin hosts.
- Malicious: a non-analyst endpoint resolving `1vpns.com` and following with an outbound TLS connection, or a host with a stored OpenVPN profile or WireGuard config naming the service. Particularly malicious if the endpoint also has data-staging activity (file copy to USB, archive creation, Rclone process tree) within the same shift.

## Data sources
- Defender XDR — `DeviceNetworkEvents` (outbound), `DeviceFileEvents` (config-file persistence), `DeviceProcessEvents` (Rclone / 7zip / WinRAR creation).
- Zeek — `dns.log`, `ssl.log`, `conn.log` from the corporate egress span.
- Corporate web proxy access log.
- DLP and CASB telemetry — egress volume + destination correlation.

## Search logic
- DNS — see Sigma rule [`../sigma/firstvpn_outbound_dns_corp_endpoint.yml`](../sigma/firstvpn_outbound_dns_corp_endpoint.yml).
- Endpoint outbound — see KQL [`../kql/firstvpn_corp_endpoint_outbound.kql`](../kql/firstvpn_corp_endpoint_outbound.kql).
- Suricata egress — see [`../suricata/firstvpn_dns_tls_egress.rules`](../suricata/firstvpn_dns_tls_egress.rules) (sids 8230001-8230007).
- YARA on endpoint disk for stored client config — see [`../yara/firstvpn_client_config_artifacts.yar`](../yara/firstvpn_client_config_artifacts.yar). Run against `%AppData%`, `%LocalAppData%`, `%UserProfile%\Documents`, and removable-media mount points.

## Time window
Six months retroactive on EDR (DeviceNetworkEvents typically capped at 30-180 days); two years retroactive on Zeek archive if available; ongoing for live detection.

## Action on match
1. Interview the user: do they have business justification (red-team engagement, research)?
2. If no justification, pull the user's last 30 days of activity — file access, email outbox, USB events, cloud-storage uploads.
3. Image the endpoint for forensic preservation if data-staging signals are present in the same shift; preserve `prefetch`, `amcache`, registry hives, browser history before reboot.
4. If the user is a contractor: review contractor onboarding and offboarding records; correlate against Day 22 lesson on contractor / RMM tier-0 exposure. Day 24's `/proc/<PID>/mem` CI/CD secret-jar primitive is an adjacent risk if the contractor has runner access.
5. Escalate to legal/HR per insider-risk policy if intent is malicious.

## Notes
- Pair with cloud-storage telemetry: a successful outbound to First VPN frequently precedes upload of staged data to Mega, Wasabi, MediaFire, or a custom S3 endpoint with non-corporate credentials.
- Consider blocking the customer-facing domains at the corporate DNS resolver as a low-friction preventive control, with a logged exception path for security-research workstations.
