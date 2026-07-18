# PEAK Hunt H2 — Ghost Operator route mismatch (IR.21 vs observed OPC / Route-Record)

**Hypothesis.** A signalling identity used against our subscribers does not enter our network through the interconnect path its own IR.21 filing declares. If true, the Originating Point Code (SS7) or Route-Record/Origin-Host pair (Diameter) observed in traffic differs from the provider that operator's IR.21 documentation says should be carrying its traffic — the "Ghost Operator" pattern Citizen Lab used to fingerprint STA1 (Table 3, Table 7).

**Why this is the durable signal.** GT and hostname spoofing changes per campaign, but the *IR.21-vs-observed-transit* mismatch is structural: it exists whenever an actor buys or compromises indirect access rather than being the operator itself. STA1 sustained this pattern for 12+ months (Table 8) using the same handful of hostnames, because building a new interconnect relationship is far more expensive than rotating a GT.

**Data.** Operator IR.21 documents (GSMA roaming database) cross-referenced with observed OPC/Route-Record and BGP/ASN data from the interconnect provider. See `../sigma/01_diameter_cross_realm_origin_spoof.yml` and `../kql/01_diameter_cross_realm_mismatch_syslog.kql`.

**Run.**
1. Pull the current IR.21 filing for every operator identity seen originating signalling traffic in the last 30 days; record its declared interconnect/IPX provider(s).
2. For each observed message, extract the actual transiting OPC (SS7) or the IPX provider inferred from Route-Record/DNS/BGP (Diameter).
3. Diff declared vs observed provider per operator identity; rank by message volume and by whether the target subscriber is a protected-personnel MSISDN.
4. For persistent mismatches, check DNS resolution of the Origin-Realm domain — an authoritative NXDOMAIN on a domain that is nonetheless BGP-reachable (per the 019Mobile case, ASN 51825 via AS12400) is a strong secondary confirmation of deliberate concealment, not misconfiguration.

**Triage / expected vs benign.** Benign: a recent IPX provider migration not yet reflected in IR.21 (check the operator's public change notices), or a small MVNO legitimately routing through a shared parent-operator's IPX. Suspicious: a mismatch that recurs across months against the same OPC/hostname pair, especially paired with cross-realm Origin-Host/Origin-Realm spoofing (H1's escalation partner, sid `4100002`).

**Pivots.** Other target networks reached through the same mismatched transit path (STA1 reused Tango Networks UK and 019Mobile across at least nine countries); the specific IPX provider that failed to screen the mismatch (Syniverse in the AIS/China Unicom case) — a screening-failure finding is worth escalating to that IPX provider directly, independent of the specific attacker.
