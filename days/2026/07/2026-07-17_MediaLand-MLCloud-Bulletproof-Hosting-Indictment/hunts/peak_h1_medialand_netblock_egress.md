# PEAK Hunt H1 — Retrospective Egress to Media Land / ML.Cloud Netblocks

## Hypothesis

If any monitored endpoint has ever connected outbound to Media Land LLC (AS206728)
netblocks (`45.141.85.0/24`, `91.220.163.0/24`), that traffic represents either
(a) benign historical contact with content that happened to be fronted by
bulletproof-hosted infrastructure, or (b) a compromised host beaconing to
rented command-and-control. Because Media Land has operated since roughly 2015
and hosted a wide variety of content types, a single historical hit is weak
evidence on its own.

## Type

Baseline/model-driven retrospective hunt (PEAK).

## Data sources

- Firewall/proxy egress logs or NetFlow/IPFIX records covering at least the
  preceding 12 months (BPH tenancy on a given IP can be long-lived)
- `DeviceNetworkEvents` (Defender XDR) or equivalent EDR network telemetry
- Passive DNS history for any domain associated with a flagged connection

## Procedure

1. Run `kql/medialand_netblock_egress.kql` (or the firewall-log grep equivalent
   from the README IR playbook) against the full available retention window.
2. For each hit, resolve the initiating process, account, and destination
   port/URL.
3. Cross-reference the destination IP against passive DNS to determine what
   domain(s) it served at the time of the connection.
4. Corroborate with H2 (fast-flux DNS pattern) and H3 (tunneling-binary
   execution) before escalating any single host to incident status.
5. Document all findings — even benign ones — since Media Land's tenancy
   patterns are useful context for future retrospective hunts as more of its
   historical infrastructure becomes attributable via the April 2025 leak
   dataset.

## Expected outcome

A ranked list of hosts with historical connections to the sanctioned
netblocks, annotated with corroborating signals (or their absence), feeding
the IR triage process in the case README.

## Related

- `sigma/network_connection_medialand_netblock_egress.yml`
- `kql/medialand_netblock_egress.kql`
