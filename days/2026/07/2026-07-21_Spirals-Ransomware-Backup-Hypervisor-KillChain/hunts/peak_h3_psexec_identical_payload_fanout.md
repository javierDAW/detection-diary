# PEAK Hunt H3: PsExec Identical-Payload Fan-Out

**Author:** Jarmi
**Date:** 2026-07-21
**Case:** Spirals ransomware
**Hypothesis type:** Situational hunt (lateral movement)

## Hypothesis

*If* an attacker is using PsExec for mass internal ransomware deployment,
*then* one source host will open many near-simultaneous PsExec sessions
carrying an identical (or near-identical) base64-encoded PowerShell payload
to distinct targets, at a fan-out rate distinguishable from legitimate
administrative PsExec usage.

## Why this matters

Spirals pushed the same base64-encoded PowerShell blob to more than one new
target every few seconds for roughly 30 minutes from a single host,
following an earlier WMI-based lateral-movement phase. The combination of
payload-identity and fan-out rate is a strong automation signature that
legitimate ad hoc admin use of PsExec rarely produces.

## Data sources

- EDR process-creation telemetry (`DeviceProcessEvents` or Sysmon EID 1)
  for `psexec.exe`/`psexec64.exe` command lines
- Windows Security Event ID 5140/5145 (network share object access) on
  target hosts for the `ADMIN$` share PsExec uses
- Source-host outbound connection telemetry to distinguish one-to-many
  fan-out from normal one-to-one remote administration

## Procedure

1. Query `DeviceProcessEvents` for `FileName in ("PsExec.exe","PsExec64.exe")`
   over the trailing 14 days, extracting `InitiatingProcessAccountName`,
   source `DeviceName`, and the encoded payload portion of
   `ProcessCommandLine`.
2. Group by source host and 30-minute time bucket; compute the count of
   distinct destination hostnames referenced in the command line or
   inferred from paired remote-execution telemetry.
3. Flag any source host/bucket with more than 5 distinct destinations
   AND a matching (or near-identical, allowing for per-host token
   substitution) base64 payload string across sessions.
4. For flagged hosts, retrieve the decoded PowerShell payload (if captured
   by script-block logging or EDR) and check it against the known Spirals
   pattern: Defender disablement followed by the 23-service Stop-Service
   sweep (see H2).
5. Escalate any match as probable active ransomware staging, not a hunt
   finding for later review.

## Expected legitimate activity (false positives)

Enterprise software deployment or patch-management tools (SCCM, third-party
RMM platforms) that legitimately use PsExec-style remote execution at
scale; these should be excluded by known service-account identity and by
the absence of Defender-disablement or backup-service-kill payload content.

## Related detections

`kql/spirals_psexec_fanout.kql`
