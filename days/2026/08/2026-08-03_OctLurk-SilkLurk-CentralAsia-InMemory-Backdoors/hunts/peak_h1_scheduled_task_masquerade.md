# PEAK Hunt H1 - GoogleUpDate / AnyDesk Scheduled-Task Masquerade

- Author: Jarmi
- Date: 2026-08-03
- Frame: PEAK (Prepare, Execute, Act with Knowledge)
- MITRE: T1053.005 (Scheduled Task), T1036.005 (Match Legitimate Name)

## Hypothesis
An OctLurk operator with admin credentials has created a scheduled task named `GoogleUpDate`
(SYSTEM, run-once) to execute `1.bat`/`in.bat`, and/or an `AnyDesk` task that runs a keylogger
on every logon. If present, at least one host in the estate has a task whose name imitates
Google Update or AnyDesk but whose action is a `.bat` or an executable under a user-writable
path (Videos, Desktop, Users\Public, ProgramData).

## Data sources
- Defender XDR `DeviceProcessEvents` (schtasks.exe /create), `DeviceEvents` (ScheduledTaskCreated).
- Windows Security 4698 (task created) / Microsoft-Windows-TaskScheduler/Operational 106.
- Registry `\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\GoogleUpDate`.

## Execute
1. Enumerate all tasks named GoogleUpDate or AnyDesk across the fleet; capture the action path.
2. Flag any where the action is a `.bat` or an executable outside a signed vendor directory.
3. Pivot on the creating account and the creation time; correlate with service creation
   (NgcCIntSvc / Cusrxsrv / RmSs) in the same window (see H2).

## Act
- True positive: quarantine host, collect the batch/DLL, hunt the C2 (H3), rotate the abused
  admin credential. False positive: genuine Google Update tasks register services, not batch
  actions named GoogleUpDate - document and baseline.

## Notes
Linked Sigma: proc_octlurk_scheduled_task_masquerade.yml. Linked KQL:
octlurk_scheduled_task_masquerade.kql.
