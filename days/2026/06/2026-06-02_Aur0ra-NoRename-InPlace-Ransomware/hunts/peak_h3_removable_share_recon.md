# PEAK Hunt H3 — Pre-encryption peripheral and network-share reconnaissance

- **Hypothesis:** A sandbox-aware binary enumerates the USB bus and network shares shortly before impact, so it can reach removable media and mapped drives in addition to local files. Aur0ra's CYFIRMA mapping includes Peripheral Device Discovery (T1120) and Network Share Discovery (T1135).
- **MITRE:** T1120 (Peripheral Device Discovery), T1135 (Network Share Discovery)
- **Data sources:** Defender XDR `DeviceProcessEvents`; Sysmon EID 1; Windows Security 4688.

## Prepare

Baseline inventory/asset-management agents and admin scripts that legitimately enumerate disks, USB devices, and shares. This hunt is medium-fidelity alone; its value is as an early-warning lead that should be chained with H1 (recovery inhibition) or H2 (modification burst) on the same host.

## Execute

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("Win32_USBHub", "Win32_PnPEntity", "Win32_LogicalDisk"))
     or (FileName =~ "net.exe" and ProcessCommandLine has_any (" view", " share", " use"))
| summarize DiscoveryCmds = make_set(ProcessCommandLine, 20), CmdCount = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, AccountName, InitiatingProcessFileName
| order by CmdCount desc
```

## Act / Analyze

Correlate any host appearing here with H1/H2 within a short window. A host that enumerates USB + shares and then deletes shadow copies or starts a modification burst is the full pre-encryption sequence — escalate immediately. On its own, treat as a lead and enrich with the initiating process lineage.
