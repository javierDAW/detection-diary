# PEAK Hunt H3 — DDoSia C2 infrastructure tracking (CTI tradecraft)

**Hypothesis.** Because DDoSia's Tier-1 C2 servers are public-facing and rotate on a short (~9-day) cadence, they can be enumerated proactively and blocked before our users' hosts (or our upstreams) reach them, and the fresh target list can be recovered to warn likely victims.

**Prepare.** Data sources: ThreatFox (abuse.ch) DDoSia tag, the SEKOIA-IO/Community DDoSia IOC repo, internet-wide scan data (Shodan/Censys), and passive DNS. Reference behavior: Tier-1 servers answer the client on TCP/80, expose `/client/login` and `/client/get_targets`, and historically returned an `nginx/1.18.0 (Ubuntu)` Server header.

**Execute.**
1. Pull the latest DDoSia C2 indicators from ThreatFox and the SEKOIA Community repo; do not reuse stale addresses.
2. Pivot on the server fingerprint: hosts on TCP/80 that respond to `/client/login` / `/client/get_targets` with the expected banner/behavior, in the scanning corpus.
3. Where a valid volunteer identity is available in a sanctioned research setting, recover and decrypt the target list (AES-GCM: key = (token/5)+last-32-hex of User-Hash; IV = first 12 ciphertext bytes; TAG = last 16) to enumerate current targets.
4. Track new servers over time; correlate registration/hosting patterns and the ~9-day churn to anticipate the next rotation.

**Act.** Push fresh C2 to egress blocking with a short TTL. Warn entities appearing on the recovered target list. Feed observations to the takedown pipeline — note that Operation Eastwood (July 2025) and the July-2026 Palencia arrest disrupted personnel but the infrastructure and volunteer base persist.

**Notes.** This hunt is intelligence-led and forward-looking; its value is the short-lived, refreshed blocklist and victim pre-warning, not a durable static IOC set.
