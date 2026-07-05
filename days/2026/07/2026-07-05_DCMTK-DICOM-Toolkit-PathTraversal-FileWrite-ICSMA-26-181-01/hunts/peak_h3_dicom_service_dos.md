# PEAK Hunt H3 - DICOM service crash / memory-exhaustion DoS (PACS availability)

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1499.004 Endpoint Denial of Service: Application or System Exploitation.

## Hypothesis
An adversary is sending crafted DICOM objects that crash or exhaust the imaging service - the
memory-leak DoS in DCMTK (CVE-2026-50254 / CVE-2026-35505), the type-confusion crash (CVE-2026-44628),
or the Grassroots DICOM allocation bomb (CVE-2026-3650, ~150 bytes -> up to 4.2 GB). Impact is loss of
PACS availability: an imaging archive taken offline or diagnostic workstations frozen mid-read, which
in a hospital is a patient-safety event, not just an outage.

## Prepare - data sources
- EDR process telemetry: `DeviceProcessEvents` (WerFault, short-lived receiver starts), auditd.
- OS/service logs: Windows Service Control Manager restart events; systemd `Restart=` churn on Linux.
- Host memory/performance metrics for the imaging hosts (RSS spikes on the receiver process).
- Suricata association events (SID 2026070501/2026070502) to tie a crash to a preceding association.

## Execute - logic
1. Find WerFault for a DCMTK binary, or a DICOM receiver restarting >= 5 times in a 10-minute window -
   see `kql/dcmtk_process_crash_dos.kql`.
2. For each crash cluster, pull the preceding inbound association (H1) and the source IP that sent the
   object immediately before the crash.
3. Correlate a receiver RSS spike (toward multi-GB on a small transfer) with GDCM-based products -
   the allocation-bomb signature of CVE-2026-3650.
4. Distinguish a single crash (possible malformed-but-benign object) from a repeating pattern tied to
   one source (deliberate DoS).

## Act - triage
- **Confirmed DoS:** repeated receiver crashes / restart loop or a multi-GB allocation on a tiny
  transfer, tied to a specific source association. Block the source; failover the archive if available.
- **Escalation:** the same source also appears in H1 (external) or H2 (file write) - a multi-CVE
  operator, not a fuzzing accident.
- **Benign:** a one-off crash from a genuinely malformed study; capture the object for vendor analysis
  and confirm it does not repeat.

## Knowledge - notes
Record the crashing object (quarantine a copy), the source, and the receiver version. GDCM CVE-2026-3650
had no fix at disclosure and the maintainer was unresponsive, so for GDCM-based products the control is
compensating: rate-limit and size-bound inbound objects, segment the receiver, and alert on RSS growth
rather than waiting for a patch.
