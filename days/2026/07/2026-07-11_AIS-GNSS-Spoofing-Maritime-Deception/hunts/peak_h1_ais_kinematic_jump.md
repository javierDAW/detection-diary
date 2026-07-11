# PEAK Hunt H1 — AIS kinematic implausible-jump (Stage 1 PSE)

**Hypothesis.** Vessels transiting a contested area report AIS positions consistent with GNSS spoofing: a position jump between consecutive fixes that is too large, and an implied speed no surface vessel can sustain. Each such fix is a candidate potential spoofing event (PSE).

**Prepare.** Data sources: a decoded-AIS position feed (AIVDM message types 1/2/3) landed in a SIEM table (`AisPosition_CL`) or a pandas dataframe from a `pyais`-decoded capture. Fields needed per record: MMSI, UTC time, latitude, longitude, seconds field, message type. Establish the receiving station's revisit interval so satellite-AIS latency does not masquerade as a jump.

**Execute.**
1. Sort each MMSI's positions by time; for each consecutive pair compute the great-circle distance and the implied speed over the elapsed interval.
2. Apply SeaSpoofFinder's Stage-1 data-quality filters first: discard records with any zero coordinate, with a seconds field greater than 59, with a placeholder MMSI ending `000000`/`999999`, and jumps that are almost purely N/S or E/W (coordinate bit-error artifacts).
3. Flag pairs where distance exceeds the jump threshold (start ~5 km) and implied speed exceeds a physical ceiling (start ~120 kn); tune both to the station.
4. Record each PSE as `{mmsi, prev_lat, prev_lon, curr_lat, curr_lon, distance_m, dt_s, implied_kn, prev_time_utc, curr_time_utc}`.

**Act.** PSEs alone are noisy — pass them to H2 for spatial clustering before escalating. Retain per-vessel trajectories for any MMSI with repeated PSEs.

**Notes.** This is intentionally conservative and prioritizes false-alarm reduction over recall; a simple pairwise jump detector on raw data flags many benign "jumping" vessels. Back-to-port jumps and receiver hand-off gaps are the dominant false positives.
