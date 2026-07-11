# PEAK Hunt H2 — Multi-vessel spoof-cluster convergence (Stage 2 FPSE)

**Hypothesis.** A GNSS spoofing source affects every receiver in its footprint, so multiple vessels lock onto the same counterfeit signal and report near-identical positions. Two or more MMSIs jumping from a common source area to a near-identical destination is the multi-receiver spoofing signature that a single-vessel jump cannot confirm — a final potential spoofing event (FPSE).

**Prepare.** Data source: the Stage-1 PSE set from H1 (`AisPositionJump_CL`). Choose a source-area radius (~10 km) and a destination cell (~10 m). Load a coastline / port polygon layer to recognise dense-anchorage false positives.

**Execute.**
1. Bucket PSE destinations into ~10 m cells and a short time window (start ~15 min).
2. Retain cells where at least two distinct MMSIs converge; require that their pre-jump positions came from a common ~10 km source area (excludes coincidental co-location).
3. Score by vessel count and event density; map the FPSE footprints. Recurrent footprints appear over the Baltic (Kaliningrad, St. Petersburg), Murmansk, the Black Sea, and the eastern Mediterranean / Haifa.
4. Add the circular-trajectory test: flag vessels whose spoofed track traces a persistent circle around a fixed point — a classic GNSS-spoofing artifact (positions dragged onto a repeating orbit).

**Act.** Treat an FPSE footprint as an area GNSS-denial/spoofing event: issue a navigation-safety advisory, switch affected units to inertial / celestial / radar fallback, and log the window for correlation with H3 identity-spoofing and with GNSS fix-degradation telemetry.

**Notes.** AIS-only evidence characterises but does not attribute — the paper is explicit that source attribution needs independent RF observation. Amsterdam, Stockholm and Fort Lauderdale produce recurring non-spoofing artifacts (back-to-port jumps, data gaps) that still pass Stage-1 filters, so keep the clustering and source-separation constraints strict.
