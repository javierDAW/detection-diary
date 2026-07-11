# PEAK Hunt H3 — AIS identity spoofing and dark-fleet deception

**Hypothesis.** Vessels deliberately falsify their AIS identity — name, MMSI, flag or ship type — to deceive observers, launder sanctioned cargo, or mask origin and intent. The IFC AOR reported 40 such incidents in June 2026, all involving vessels transmitting false AIS information. The tells are placeholder/invalid identifiers, generic labels, flag-versus-MMSI mismatch, and identity churn per physical transponder.

**Prepare.** Data source: decoded AIS static/voyage records (message type 5) in `AisStatic_CL`, joined to a vessel registry (name/MMSI/flag/callsign/IMO ground truth) and to the MMSI Maritime Identification Digits (MID) country table. Load choke-point polygons (Strait of Hormuz, Black Sea, Gulf of Oman, South China Sea, eastern Mediterranean).

**Execute.**
1. Flag static records with a placeholder MMSI (ends `000000`/`999999`) or a generic name (`NATO SHIP`, `FRENCH WARSHIP`, `SAMPLE`).
2. Compute MID-versus-flag mismatch: the country implied by the MMSI's leading digits should agree with the reported flag; a mismatch is a spoofing/reflagging tell (corroborate against second-registry data before escalating).
3. Detect identity churn: the same physical transponder (correlate by IMO, callsign, or a stable position track) advertising different MMSI/name over time, especially a switch to another real vessel's identity.
4. Correlate "going dark" then re-appearing: an AIS gap followed by re-emergence under a new identity inside a sanctions choke point.

**Act.** Build a watchlist of suspect MMSIs/identities; enrich port-call and cargo records; share with the relevant reporting centre. Treat a confirmed identity switch in a choke point as a sanctions-evasion indicator, not a mere data error.

**Notes.** Unlike GNSS spoofing (an RF attack on the position source), identity spoofing is a data-layer manipulation of the self-reported AIS payload — AIS has no authentication or replay protection by design, so the report is trusted only as far as it can be cross-checked. Flag-of-convenience registration and legitimate reflagging are the main false positives.
