# PEAK Hunt H1 - Exposed DICOM listeners and associations from outside the imaging VLAN

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1190 Exploit Public-Facing Application; T1595.002 Active Scanning: Vulnerability Scanning.

## Hypothesis
A DICOM Storage / Query-Retrieve SCP built on OFFIS DCMTK (<= 3.7.0) is reachable from outside the
imaging VLAN and is receiving associations from unexpected sources. Exposure is the precondition for
every ICSMA-26-181-01 CVE: any peer that can open an association can drive the path-traversal file
write (CVE-2026-50003) or the memory-exhaustion / type-confusion DoS. A DICOM SCP should only ever be
associated with by known modalities and archives inside the imaging VLAN.

## Prepare - data sources
- EDR network telemetry: Defender XDR `DeviceNetworkEvents` (`InboundConnectionAccepted`), Sysmon EID 3.
- Firewall / NetFlow for tcp/104, tcp/11112, tcp/2762, tcp/2761.
- Suricata `dicom_dcmtk_cve_2026.rules` (association PDU and AE-title events) on the imaging VLAN span.
- Asset inventory / SBOM: which hosts run DCMTK-derived receivers and at what version.

## Execute - logic
1. Enumerate every host accepting inbound connections on 104 / 11112 / 2762 / 2761 - see
   `kql/dicom_inbound_listener_external.kql` and `sigma/dicom_inbound_association_external.yml`.
2. Subtract the known modality and archive ranges; whatever remains is an association from an
   unexpected origin.
3. For Suricata hits, group by source IP and by advertised AE title (SID 2026070502) to separate
   legitimate modalities from scanner AE titles (`ECHOSCU`, `FINDSCU`, `STORESCU`, `DCMTK`).
4. Cross-reference each listening host's DCMTK version against 3.7.1; flag any at or below 3.7.0.

## Act - triage
- **Confirmed exposure:** a DICOM SCP reachable from a non-imaging or external source, running
  DCMTK <= 3.7.0. Treat as internet-facing critical - segment first, patch second.
- **Escalation:** exposure plus H2 (file write outside the store) or H3 (crash loop) from the same
  window means active exploitation, not just exposure.
- **Benign:** an in-VLAN modality or PACS peer on the allowlist; confirm against the asset inventory.

## Knowledge - notes
Record each exposed listener, its DCMTK version, and the source ranges reaching it. DICOM has no
transport authentication in most deployments, so network reachability is effectively authorization -
segmentation and a firewall allowlist are higher-leverage than any single patch.
