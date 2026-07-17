# PEAK Hunt H3 — Tunneling-Binary Execution Preceding BPH Egress

## Hypothesis

If a host executes a reverse-proxy or tunneling binary (`stunnel`, `socat`,
`frpc`, `ngrok`) and then originates new outbound connections to a
previously-unseen Russia-hosted ASN within the same session, that combination
is a higher-confidence indicator of intentional infrastructure bridging
toward bulletproof hosting than either signal alone.

## Type

Hypothesis-driven hunt (PEAK) — process/network correlation.

## Data sources

- `DeviceProcessEvents` / Sysmon EID 1 (process creation)
- `DeviceNetworkEvents` / Sysmon EID 3 (network connection)
- Asset inventory (to determine whether a host has a legitimate business
  reason to run tunneling tools)

## Procedure

1. Run `kql/tunnel_binary_execution.kql`, which joins tunneling-binary
   execution to network connections toward the sanctioned Media Land
   netblocks within a 1-hour window of execution.
2. For each match, check the asset inventory / change-management records for
   an approved use case (e.g., an approved remote-access bridge).
3. For any match without a documented business justification, escalate per
   the README's "First 60 minutes" triage steps.
4. Extend the same join pattern to other RU-hosted ASNs of interest as they
   are identified (this hunt's logic generalizes beyond Media Land alone).

## Expected outcome

Zero or near-zero matches in a healthy environment; any match without a
documented justification should be treated as a priority triage item, since
the combination of tunneling-tool execution plus fresh egress to sanctioned
BPH space is not something legitimate business workflows typically produce
together.

## Related

- `sigma/process_creation_tunnel_binary_preceding_bph_egress.yml`
- `kql/tunnel_binary_execution.kql`
