# PEAK Hunt H1 — Multi-GT provideSubscriberInfo burst against a single subscriber

**Hypothesis.** A surveillance platform (STA1-class) is probing a single high-value subscriber with `provideSubscriberInfo` (PSI) location queries sent within minutes of each other from Global Titles belonging to multiple, geographically unrelated operators. If true, the SS7 firewall log for that IMSI/MSISDN shows a burst of PSI attempts from GTs in different countries within a 5-10 minute window, none of which are on the subscriber's own roaming partner list for that window.

**Why this is the durable signal.** Individual GTs rotate across campaigns and can be leased or spoofed, so blocking any one GT is a losing game. What is durable is the *behaviour*: a legitimate roaming registration touches one or two partner networks, while STA1's 2024-11-25 campaign cycled through GTs in Cambodia, Mozambique, Sweden, Italy, Liechtenstein and Uganda against one target inside three minutes — a rate and geographic spread no real subscriber journey produces.

**Data.** SS7 signalling-firewall export (Cellusys/Enea/P1 Security/Mavenir class product), normalised into `Syslog` via CEF. See `../sigma/02_ss7_anytimeinterrogation_escalation.yml` for the escalation half of this chain and `../kql/02_ss7_ati_escalation_syslog.kql` for the correlated query.

**Run.**
1. For each target IMSI/MSISDN, bucket `provideSubscriberInfo` and `sendRoutingInfoForSM` events into 10-minute windows.
2. Count distinct source-GT countries per window; flag windows with 3 or more distinct countries against the same target.
3. Cross-reference each source GT against the target operator's IR.21 roaming-partner list; flag GTs that are not listed partners for that timeframe.
4. Check whether the burst is followed (same target, within 2 hours) by an `anyTimeInterrogation` or a Diameter `Insert-Subscriber-Data-Request` — this indicates the actor is escalating after PSI is throttled or blocked.

**Triage / expected vs benign.** Benign: a subscriber crossing borders and re-registering with 2-3 networks in sequence over hours, or a lawful roaming-quality-monitoring platform querying a small fixed partner set. Suspicious: 3+ unrelated countries inside minutes against one target, especially when combined with GTs absent from IR.21, or a subscriber flagged internally as VVIP/protected personnel.

**Pivots.** Reused GTs across other targets/timeframes (build a GT reputation table from `feeds/iocs_all.csv`); the ASN/IPX provider each GT actually transited (compare against IR.21-expected provider, Table 3/Table 7 pattern in the Citizen Lab report); whether the same target later shows an anomalous enterprise sign-in (see H3).
