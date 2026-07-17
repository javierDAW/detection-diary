# PEAK Hunt H2 — Fast-Flux DNS Resolution Pointing Into Media Land Space

## Hypothesis

If a resolved domain shows three or more A records with sub-600-second TTLs
and at least one resolved IP falls inside AS206728 (or historically
Media-Land-adjacent space), that domain is likely a fast-flux bulletproof
hosting front-end regardless of its apparent content category. This mirrors
the modus operandi Spamhaus documented across BPH operators since 2019 and
that DOJ/OFAC filings describe as a core Media Land/ML.Cloud service offering.

## Type

Model-driven hunt (PEAK) — pattern-based, not signature-based.

## Data sources

- Recursive DNS resolver query logs with TTL and multi-A-record visibility
- Passive DNS aggregation feed (internal or commercial)
- `docs/data.json`-style IOC context is not sufficient here; this hunt needs
  raw resolver telemetry

## Procedure

1. Run `kql/fastflux_dns_pattern.kql` against the available DNS query table
   (adjust the `<add_known_dns_query_table>` placeholder to the environment's
   actual DNS logging table/connector).
2. For each candidate domain, verify: (a) record count >= 3, (b) minimum TTL
   <= 600s, (c) at least one resolved IP in `45.141.85.0/24` or
   `91.220.163.0/24`.
3. Exclude known-legitimate CDN/anycast ranges before triaging remaining
   candidates as likely BPH front-ends.
4. For confirmed fast-flux domains, add to the internal DNS blocklist/sinkhole
   and check historical resolver logs for any internal host that queried them.

## Expected outcome

A short list of domains exhibiting fast-flux behavior into Media Land space,
each either already known-malicious (cross-check `iocs.csv` and public
threat-intel feeds) or newly discovered and worth submitting to community
threat-intel sharing.

## Related

- `sigma/network_connection_medialand_netblock_egress.yml`
- `kql/fastflux_dns_pattern.kql`
