# PEAK Hunt H1 — Dire Wolf recovery-inhibition burst

**Hypothesis (P).** A Dire Wolf intrusion will, on at least one host, spawn two or more recovery-denial commands (`vssadmin delete shadows`, `wbadmin delete backup`, `bcdedit ... recoveryenabled No` / `bootstatuspolicy ignoreallfailures`) from a single parent process within a short window, before any file is renamed to `.direwolf`.

**Why it works.** Stage 5 of the kill chain runs before encryption, so this fires earlier than any extension- or canary-based rule. The clustering of multiple distinct recovery-denial commands from one parent is what separates ransomware from routine backup maintenance.

**Enrich (E).** Pull process-creation telemetry (Sysmon EID 1 / Security 4688 / `DeviceProcessEvents`). Group by host + initiating process + 10-minute bin; count distinct recovery commands.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadow")
     or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete backup","delete systemstatebackup"))
     or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled No","bootstatuspolicy ignoreallfailures"))
| summarize n=dcount(ProcessCommandLine), cmds=make_set(ProcessCommandLine,16) by DeviceName, InitiatingProcessFileName, bin(Timestamp,10m)
| where n >= 2
```

**Analyze (A).** A host with >=2 distinct recovery-denial commands from one parent in 10 minutes is a strong lead. Single benign invocations (one backup tool pruning shadows) are expected; the burst is not.

**Knowledge (K).** Baseline the maintenance hosts and backup products that legitimately prune shadows/catalogs. Promote H1 to the `sigma/direwolf_inhibit_recovery_burst.yml` alert with SIEM-side thresholding once the benign set is documented.
