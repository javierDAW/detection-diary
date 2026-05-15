# PEAK H3 — GoTo Resolve installed on DC plus GPO write to SYSVOL within 24h

## Hypothesis

A GoTo Resolve service install on a domain controller, file server, hypervisor host, or application server, followed within 24 hours by an executable, DLL, PowerShell, or batch script write to `\\<dc>\SYSVOL\` or `\\<dc>\NETLOGON\`, signals the final stage of a ransomware fan-out preparing to detonate domain-wide via a malicious Group Policy Object. This pattern was observed by The DFIR Report TB40048 (May 2026) immediately before The Gentlemen ransomware encryption.

## Why this discriminates

DCs and tier-0 systems must never carry third-party RMM. The combination of an RMM install on tier-0 plus a SYSVOL or NETLOGON write within a short window is the canonical pre-ransomware-fan-out shape, used by Akira (with ScreenConnect), Black Basta (with AnyDesk), Conti predecessors (TeamViewer), and now The Gentlemen with GoTo Resolve. This is the last reliable detection moment before encryption.

## Query — KQL (Defender XDR)

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where ProcessCommandLine has_any ("GoToResolveProcessChecker", "GoTo Resolve Unattended")
   and InitiatingProcessFileName =~ "msiexec.exe"
| where DeviceName matches regex @"(?i)(dc|sql|file|hyperv|esx|app)\d*[\.\-]"
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName,
          CommandLine = ProcessCommandLine
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(3d)
    | where FolderPath has_any (@"\SYSVOL\", @"\NETLOGON\")
    | where ActionType in ("FileCreated", "FileModified")
    | where FileName endswith ".exe" or FileName endswith ".dll"
         or FileName endswith ".ps1" or FileName endswith ".bat"
    | project GpoTimestamp = Timestamp, DeviceName, FileName, FolderPath
) on DeviceName
| where (GpoTimestamp - Timestamp) between (-1h .. 24h)
```

## Expected benign

- Legitimate GoTo Resolve installs on selected admin workstations are fine. The discriminator is the device tier — DCs, file servers, hypervisor hosts, and application servers should never carry third-party RMM.
- Genuine GPO content updates by a domain admin will land in SYSVOL. The discriminator is the **co-occurrence** with an RMM install on the tier-0 host.

## Expected malicious

- GoTo Resolve service installed on a DC or tier-0 server, followed by a `.exe`, `.dll`, `.ps1`, or `.bat` write to SYSVOL or NETLOGON within 24 hours.
- The SYSVOL change references a scheduled task xml or a startup script GPO that points at a binary unknown to the IT inventory.

## Action on match

1. Disconnect the DC at the network layer immediately — this is the last moment before fan-out detonation.
2. Freeze AD replication on neighbouring DCs (`repadmin /options $DC +DISABLE_OUTBOUND_REPL`).
3. Identify and delete the malicious GPO. Snapshot SYSVOL contents for forensics before deletion.
4. Engage the IR playbook in the parent `README.md`, sections "Containment, eradication, recovery" — focus on `krbtgt` double rotation, `kerberos ticket lifetime` reduction, and gold-image rebuild of affected hosts.
5. Notify GoTo (and any other RMM vendor in use) so they can revoke the operator-owned tenant or workspace.
