# PEAK Hunt H3 — EDR-Silenced Host: Post-Kill Detection When Telemetry Is Gone

## Hunt Type
Behavioral / out-of-band

## Hypothesis
After GentleKiller succeeds in terminating all security product processes, the host goes
"dark" to the EDR cloud. A host that abruptly stops sending telemetry while still network-
reachable is a high-confidence indicator of EDR kill. Detecting this silence from the
SIEM/XDR control plane — rather than from the host's own telemetry — is the only
reliable detection method after BYOVD execution.

## Rationale
GentleKiller loops through 400+ security process targets and kills them periodically.
Once the EDR kernel component is disabled, no further telemetry arrives from that host.
The defender's control plane (SIEM/XDR management) sees a host heartbeat gap while
the host remains reachable over the network. This out-of-band signal is immune to the
EDR kill itself because it runs on infrastructure the attacker cannot reach.

The same detection principle was validated in Day 14 (2026-05-12_Qilin-EDR-Killer-msimg32):
when the Qilin BYOVD chain disabled callbacks, the host disappeared from EDR reporting
while still pinging over ICMP.

## Data Sources
- XDR management console: device last-seen heartbeat gap (>5 minutes, host still reachable)
- Network monitoring: host still generating traffic (DHCP renewal, DNS, SMB) after EDR silence
- SIEM: absence of expected event volume from host (zero Security/System events for 10+ min)
- Defender XDR: DeviceInfo table last-seen timestamp correlation with host network activity

## Hunt Query (KQL)

```kql
// Identify hosts that have gone silent (no events) in last 60 minutes but were active before
let ActiveHosts = DeviceProcessEvents
| where Timestamp between (ago(2h) .. ago(1h))
| summarize LastSeen = max(Timestamp) by DeviceName
| where LastSeen > ago(90m);

let SilentHosts = DeviceProcessEvents
| where Timestamp > ago(1h)
| summarize RecentEvents = count() by DeviceName;

ActiveHosts
| join kind=leftouter SilentHosts on DeviceName
| where isnull(RecentEvents) or RecentEvents == 0
| project DeviceName, LastSeen, RecentEvents
| order by LastSeen asc
```

```kql
// Cross-check: do silent hosts still have network activity? (signs of life = EDR killed)
let SilentHosts = DeviceProcessEvents
| where Timestamp between (ago(2h) .. ago(30m))
| summarize LastProcess = max(Timestamp) by DeviceName
| join kind=leftanti (
    DeviceProcessEvents
    | where Timestamp > ago(30m)
    | summarize by DeviceName
) on DeviceName;

SilentHosts
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30m)
    | summarize NetworkEvents = count() by DeviceName
) on DeviceName
| where NetworkEvents > 0
| project DeviceName, LastProcess, NetworkEvents,
    Interpretation = "Host has network activity but no process telemetry — possible EDR kill"
| order by LastProcess asc
```

## Expected Output
Hosts that were actively sending events 1-2 hours ago, have zero process telemetry in the
last 30 minutes, but still show network activity. Any match is high-priority incident.

## Response Procedure
1. DO NOT reboot the host immediately — volatile evidence is in RAM (driver PoC code, 
   kernel structures modified by BYOVD, GentleKiller process memory)
2. Attempt live memory acquisition via Magnet AXIOM / Belkasoft / WinPmem before any action
3. Check GentlemenCollection staging path via a separate admin session
4. Isolate the host at the network layer (NAC / port shutdown) not at the OS layer
5. Review the 15-minute window before silence: driver service creation + staging dir creation
   are the key artifacts to recover from SIEM logs (they predate the silence)

## Out-of-Band Detection Options
- Hypervisor-level monitoring (VMI): if the host is a VM, hypervisor instrumentation
  survives EDR kill completely — Hyper-V, ESXi, and KVM all support introspection hooks
- Sysmon with ETW provider: ETW kernel providers (Microsoft-Windows-Kernel-Process)
  are distinct from the EDR's own ETW consumers; a second ETW consumer feeding to SIEM
  can survive if GentleKiller only targets security product processes, not generic ETW
- Network traffic anomaly: ransomware pre-encryption often has a discovery + enumeration
  phase visible at the network layer (SMB share enumeration, RPC endpoint mapper queries)
  even when host telemetry is silent
