# PEAK Hunt H3 — Credential-access burst to reverse-SSH + FileZilla exfil

**Hypothesis (P).** On or near a domain controller, a credential-access burst — `wbadmin start backup` including `ntds.dit`, `rundll32 comsvcs.dll` MiniDump of LSASS on multiple hosts, and `psql` against the `VeeamBackup` `credentials` table — is followed by a reverse-SSH tunnel (`ssh -R`) and a FileZilla SFTP transfer to an external host. This is the domain-database theft to exfiltration sequence.

**Why it works.** Each element is individually suspicious on a DC and their co-occurrence in a short window is a very high-fidelity intrusion signal that precedes ransomware by hours. It also captures the two most damaging outcomes — NTDS and Veeam credential theft — that dictate the recovery plan (double krbtgt rotation).

**Enrich (E).** Pull process creation on DC/backup hosts and cluster by host and 60-minute bin; count distinct credential-access behaviors; then look for `ssh -R` and a FileZilla process to an external IP on the same host.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| extend Behavior = case(
    FileName =~ "wbadmin.exe" and ProcessCommandLine has "ntds.dit", "ntds_wbadmin",
    FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has_any ("MiniDump","#000024","#+000024"), "lsass_comsvcs",
    FileName =~ "psql.exe" and ProcessCommandLine has "VeeamBackup" and ProcessCommandLine has "credentials", "veeam_psql",
    FileName =~ "ssh.exe" and ProcessCommandLine has " -R ", "reverse_ssh",
    "")
| where Behavior != ""
| summarize Behaviors=make_set(Behavior), n=dcount(Behavior), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, bin(Timestamp, 60m)
| where n >= 2
| order by LastSeen desc
```

**Analyze (A).** A host showing two or more distinct behaviors (especially `ntds_wbadmin` with `reverse_ssh`) in one hour is a confirmed-intrusion lead. Single sanctioned `wbadmin` backups are expected; the clustering with LSASS/Veeam/SSH is not.

**Knowledge (K).** Baseline the approved AD backup host, account and schedule, and any legitimate SSH tooling. Promote to `sigma/ntds_wbadmin_veeam_psql_credtheft.yml` with SIEM-side correlation; record the reverse-SSH and exfil IPs for the `suricata/` rules.
