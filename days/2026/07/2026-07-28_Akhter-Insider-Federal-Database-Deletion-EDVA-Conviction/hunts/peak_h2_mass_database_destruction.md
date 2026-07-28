# PEAK Hunt H2 -- Mass database destruction burst

**Author:** Jarmi
**Date:** 2026-07-28
**ATT&CK:** T1485 (Data Destruction)

## Hypothesis
A single actor issues destructive database verbs (DROP DATABASE / DETACH / DROP TABLE) or deletes
database and backup files across many stores within a short window, consistent with the ~96
databases deleted over several hours in the Akhter case.

## Prepare
- Telemetry: `DeviceProcessEvents` (CLI clients), DB server audit logs, `DeviceFileEvents` /
  Sysmon FileDelete for `.mdf/.ldf/.bak/.bacpac`, storage-array delete events.

## Execute
1. Collect destructive DB CLI invocations and DB-engine audit DROP/DETACH events.
2. `summarize` count per actor per 1h bin; flag bins with >= 3 distinct targets.
3. Correlate deletions with the preceding backup-integrity state (were immutable copies present?).

## Analyze / Act
- Confirm against approved teardown jobs; anything outside change control is an incident.
- Preserve DB transaction logs and storage snapshots before they roll off.
- Verify offline/immutable backups exist and are restorable (see IR playbook).
