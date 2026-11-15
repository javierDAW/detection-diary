# PEAK hunt H3 - Telemetry gaps correlated with voice / data path degradation and user-reported symptoms

## Prepare

- **Hypothesis:** before or during a network failure, devices go quiet (syslog silence, SNMP polling failures, NetFlow export drop) and users report degraded voice or screens before monitoring raises an alert; correlating those signals gives earlier and more precise outage scoping.
- **Why:** in the FAA ground stop of 2026-11-13, senior government sources cited by CBS said overwhelmed routers fed out-of-sync packets into ATC systems, causing static on voice lines and screens flashing or going black; the Transportation Secretary said routers / switches became overloaded with data and produced inconsistent information. These descriptions are reported, not officially confirmed, and no telemetry was published. Earlier the FAA had halted traffic in Chicago over ATC communications problems, before the nationwide stop. A local symptom that precedes a wide failure is exactly what a correlated view should catch.
- **Scope:** network devices on voice and operational-data paths, their syslog / SNMP / NetFlow feeds, and the service desk / operations log for the same period.
- **Confidence:** low to medium; telemetry gaps have many benign causes (collector outage, forwarder backlog, quiet devices).

## Execute

**Data sources:** Sentinel `Syslog` (`../kql/k3_syslog_network_device_telemetry_silence.kql`, `../kql/k1_syslog_reload_restart_burst_per_device_and_site.kql`), SNMP poller (availability and interface error counters), NetFlow / IPFIX collector, VoIP quality metrics (MOS, jitter, packet loss) if available, service desk tickets and operations logs, wire hints (`../suricata/faa_fti_router_update_failure_syslog_hints.rules`).

1. Run k3 to list devices that were logging and went silent beyond the threshold; first rule out a collector / forwarder outage (many devices silent at the same second usually means the collector).
2. For each silent device, pull SNMP reachability and interface error / discard counters for the same window, and NetFlow export volume from that device.
3. Pull voice quality metrics and service desk tickets mentioning static, one-way audio, dropped calls, frozen or black screens, by site and time.
4. Build one timeline per site: first precursor (Sigma 03), first silence (k3), first user symptom, first reload (Sigma 01), recovery.
5. Check whether syslog loss coincided with a logging configuration change (Sigma 02, `logging host` lines in config diffs) - silence caused by a logging change is a tampering indicator and goes to H2.

## Act

- **Findings handling:** per site, the lead time between first telemetry anomaly and first user-visible symptom; sites where users noticed first indicate monitoring gaps.
- **Improvements:** alert on telemetry silence for critical devices (k3 as a scheduled rule with a watchlist); monitor the syslog collector itself; send critical-device logs to two collectors; give operations staff a documented manual fallback (alternate voice path) and a fast way to report symptoms to the NOC.
- **Exit criteria:** every critical device has a defined silence threshold and an owner; the next outage drill shows the NOC alerted before users reported.

**What this hunt cannot show:** the cause of a gap; silence proves only that telemetry stopped, and a device that is overloaded may be the very thing preventing its own logs from leaving.
