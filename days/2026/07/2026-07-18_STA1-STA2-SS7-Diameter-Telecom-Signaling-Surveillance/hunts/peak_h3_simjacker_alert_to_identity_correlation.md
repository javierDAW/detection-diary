# PEAK Hunt H3 — SIMjacker/location-query alert followed by anomalous enterprise sign-in

**Hypothesis.** For protected personnel whose enterprise identity is linked to a roaming MSISDN (deployed military, executives, journalists), a telecom-layer surveillance alert (SIMjacker binary SMS, or a PSI/ATI/IDR location-query burst) is followed within hours by an anomalous sign-in to their enterprise account or an unusual physical movement pattern. If true, this is the bridge between a signal most SOCs never see (telecom signalling) and one they already monitor (identity), and it is the pattern behind the Iran-war reporting: SS7 location data used to find, then strike, specific personnel.

**Why this is the durable signal.** Telecom-layer alerts alone are hard to act on operationally — a SOC without a signalling-firewall feed has no visibility, and even with one, a single PSI hit against an unlisted GT is weak evidence. What turns it into an actionable case is *correlation*: the same protected individual showing a signalling-layer location query and a subsequent identity- or physical-security-layer anomaly is a much stronger joint signal than either alone, and it is durable because it does not depend on any single GT, hostname, or IP staying valid.

**Data.** Signalling-firewall alerts (Syslog/CEF, see `../kql/01`-`../kql/03`) joined to Entra `SigninLogs`/`IdentityLogonEvents` via a maintained MSISDN-to-UserPrincipalName watchlist for protected personnel. See `../kql/04_signaling_alert_to_signin_anomaly_correlation.kql`.

**Run.**
1. Confirm (or build, with the personnel-security/force-protection team) a watchlist mapping protected-personnel MSISDNs to enterprise UserPrincipalName — without this join key the hunt cannot run.
2. For each signalling-firewall alert (H1/H2 patterns, or a raw SIMjacker `TP-PID=127`/`TP-DCS=22` hit) against a watchlisted MSISDN, pull all sign-in events for the linked UPN in the following 6 hours.
3. Flag sign-ins that are new-ASN, new-country, or impossible-travel relative to the individual's baseline.
4. Escalate matches to force-protection / physical-security channels, not just the SOC — the operational risk here is physical, not just data-confidentiality.

**Triage / expected vs benign.** Benign: the personnel member is travelling on approved orders/itinerary and both the roaming registration and the sign-in match the expected location. Suspicious: a signalling alert against the MSISDN with no matching approved-travel record, especially clustering in the days before a planned movement or during an active conflict window.

**Pivots.** Other watchlisted MSISDNs hit by the same GT/hostname cluster in the same period (mass-targeting vs single-target); whether the alert volume against the watchlist spikes ahead of publicly reported troop movements or basing changes — a spike itself is intelligence, independent of any single confirmed hit.
