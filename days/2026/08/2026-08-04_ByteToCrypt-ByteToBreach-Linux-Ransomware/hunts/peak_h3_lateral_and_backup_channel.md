# PEAK Hunt H3 - Lateral Fan-Out and Backup Channel Before Impact

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If ByteToBreach pre-positioned before deploying ByteToCrypt, then one account drove SSH + PsExec fan-out and commodity remote-access/tunneling (AnyDesk, SystemBC, `ligolo-ng`) appeared, followed by access to or deletion of backup repositories.

## Prepare

- **ATT&CK:** T1021.004 (SSH), T1021.002 (SMB/Windows Admin Shares), T1219 (Remote Access Software), T1572 (Protocol Tunneling), T1490 (Inhibit System Recovery).
- **Data sources:** DeviceProcessEvents (Windows + Linux), DeviceNetworkEvents, auth logs, backup-server audit trails.
- **Scope:** domain controllers, jump hosts, and backup infrastructure in the hours before the first `.encrypted` event.

## Execute

```bash
# Commodity remote-access / tunneling artifacts on Unix
ps -ef | grep -Ei 'ligolo|anydesk|systembc' | grep -v grep
ss -tnp 2>/dev/null | grep -Ei 'ESTAB'   # correlate long-lived tunnels to unexpected peers
grep -RiE 'Accepted (password|publickey) for .* from' /var/log/auth.log* 2>/dev/null | tail
```

```kql
// One account driving ssh + psexec fan-out in an hour
DeviceProcessEvents
| where (FileName == "ssh") or (ProcessCommandLine has "psexec")
| extend Vector = iff(FileName == "ssh", "ssh", "psexec")
| summarize Ssh = countif(Vector == "ssh"), Psexec = countif(Vector == "psexec"),
    Devices = dcount(DeviceId) by InitiatingProcessAccountName, bin(Timestamp, 1h)
| where Ssh >= 5 and Psexec >= 1
```

```kql
// Remote-access tooling appearing shortly before impact
DeviceProcessEvents
| where FileName in~ ("anydesk.exe", "anydesk", "systembc") or ProcessCommandLine has "ligolo"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

## Act with Knowledge

- **Confirmed malicious:** one account spreading over SSH and PsExec, plus AnyDesk/SystemBC/`ligolo-ng`, immediately preceding datastore encryption and backup access/deletion.
- **Benign baseline:** legitimate admin jump-host activity; distinguish by the pairing with impact and the presence of tunneling tools not in the sanctioned toolset.
- **Feed forward:** the staging account and jump host scope the intrusion timeline; confirmed backup deletion (T1490) raises recovery to immutable/offline copies only.
