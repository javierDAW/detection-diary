# H2 — Backup destruction (Veeam delete-from-disk / WipeFile)

## Frame

Prepare-Execute-Act-Know hunt. The defining recovery-denial move was deleting the
Veeam backup chain at the repository level and secure-erasing the SQLBackup
directory with WipeFile. This is the action that turns a recoverable incident into
a catastrophic one.

## Hypothesis

If backups were targeted, we will observe Veeam repository "delete from disk" /
`Remove-VBR*` actions or a WipeFile/sdelete run against backup or web-root paths,
outside any sanctioned retention job.

## Expected benign baseline

Retention pruning removes obsolete restore points on a schedule by backup admins.
WipeFile/sdelete against SQLBackup or wwwroot by a non-admin, or Veeam mass
deletion outside the window, is anomalous.

## Action on match

Freeze the Veeam repository, confirm immutability/offsite copies, and check whether
the deletion was preceded by VM/volume/SQL destruction (H1). Treat backup-admin
credentials as compromised until proven otherwise.

## Query — Defender XDR

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("WipeFile.exe","sdelete.exe","sdelete64.exe")
         and ProcessCommandLine has_any ("SQLBackup","Backup","wwwroot","inetpub"))
     or ProcessCommandLine has_any ("Remove-VBRBackup","Remove-VBRRestorePoint","Remove-VBRBackupRepository")
| summarize Hits = count(), Cmds = make_set(ProcessCommandLine, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, AccountName
| order by Hits desc
```

## Notes

If the Veeam config/SQL database itself is forwarded, add `ALTER DATABASE` /
repository-delete events from it as a second leg.
