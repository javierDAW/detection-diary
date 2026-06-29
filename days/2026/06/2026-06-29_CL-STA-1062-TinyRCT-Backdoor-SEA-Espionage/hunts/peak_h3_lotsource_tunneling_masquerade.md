# PEAK Hunt H3 — Open-source tunnelers disguised as VMware / XDR binaries

**Hypothesis.** CL-STA-1062 stages SoftEther VPN, VNT, and Yuze (SOCKS5) for tunneling and
lateral movement, renaming them to blend in as `vmtools.exe`, `vmwared.exe`, or `XDRAgent.exe`
(T1036.005 + T1090). We expect processes with those names that lack the legitimate vendor
signature or run from non-standard paths, accompanied by long-lived outbound sessions.

**ABLE breakdown.**
- **Actor:** CL-STA-1062.
- **Behavior:** renamed tunnelers establishing covert relays; SOCKS proxying.
- **Location:** internal Windows hosts post web-shell foothold.
- **Evidence:** `DeviceProcessEvents`, `DeviceNetworkEvents` (Defender XDR), Sysmon EID 1/3.

**Data sources.** Defender XDR `DeviceProcessEvents` + `DeviceNetworkEvents`; Sysmon 1/3.

**Hunt logic (Defender XDR).**
```kql
DeviceProcessEvents
| where FileName in~ ("vmtools.exe", "vmwared.exe", "XDRAgent.exe")
| where not(FolderPath has_any (@"\Program Files\VMware\", @"\Program Files\"))
| join kind=leftouter (
    DeviceNetworkEvents
    | summarize Conns=count(), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, Conns, Ports
```

**Triage / pivots.**
1. Verify the signer; genuine VMware Tools is signed by VMware and lives under Program Files.
2. Check for SoftEther/VNT config strings and persistent outbound sessions (SOCKS/relay).
3. Correlate with H1/H2 on the same host to assemble the full intrusion timeline.

**Expected benign.** Legitimate VMware Tools / EDR agents from signed vendor paths; allowlist.

**Outcome.** Confirmed renamed tunnelers -> block, hunt the relay peer, and record the new
disguise filename for the masquerade detections.
