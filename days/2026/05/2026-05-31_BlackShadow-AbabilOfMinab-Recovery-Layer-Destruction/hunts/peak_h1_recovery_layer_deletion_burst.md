# H1 — Cross-plane recovery-layer deletion burst

## Frame

Prepare-Execute-Act-Know hunt. The Black Shadow / Ababil of Minab playbook denies
recovery by deleting across multiple planes in a short window: vCenter VMs, disk
volumes, SQL databases, and Veeam backups. No single deletion is unusual; the
burst across planes from one principal is the signal.

## Hypothesis

If recovery-layer destruction ran, a single principal (or host) issued a burst of
destructive actions spanning at least two of {vCenter Destroy_Task / PowerOffVM_Task,
Disk Management Delete Volume / format, SQL SET OFFLINE / DROP DATABASE, Veeam
delete-from-disk} within a compressed window.

## Expected benign baseline

Decommissioning and retention maintenance produce isolated deletions on one plane,
by known admins, in change windows. Cross-plane bursts from one principal outside
change control are anomalous.

## Action on match

Disable the principal, preserve surviving datastores/backups before any cleanup,
and confirm at least one immutable/offsite backup is intact. Pivot to H2 (backup
destruction) and H3 (proxied access).

## Query — Sentinel (unioned planes)

```kql
union
 (Syslog | where SyslogMessage has_any ("Destroy_Task","PowerOffVM_Task") | extend Plane="vcenter"),
 (Syslog | where SyslogMessage has_any ("SET OFFLINE","DROP DATABASE") | extend Plane="sql"),
 (DeviceProcessEvents | where ProcessCommandLine has_any ("Remove-VBRBackup","WipeFile","Delete Volume") | extend Plane="backup_disk")
| where TimeGenerated > ago(30d)
| extend Actor = coalesce(column_ifexists("AccountName",""), tostring(Computer))
| summarize Planes = make_set(Plane, 5), Events = count() by Actor, bin(TimeGenerated, 30m)
| where array_length(Planes) >= 2
| order by Events desc
```

## Notes

Forward vCenter and SQL audit events to the SIEM first — most estates do not by
default, and this hunt depends on that telemetry.
