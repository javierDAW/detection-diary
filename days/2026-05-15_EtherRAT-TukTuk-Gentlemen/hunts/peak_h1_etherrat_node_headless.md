# PEAK H1 — Headless Node from AppData reaching Ethereum RPC or TryCloudflare

## Hypothesis

Any `node.exe` or `conhost --headless` process spawning from `%LOCALAPPDATA%\<random>\` while loading a `.cfg` or `.ini` argument, followed within five minutes by an outbound connection to `1rpc.io`, `arweave.net`, or any `*.trycloudflare.com` host, is a near-certain compromise by EtherRAT (DPRK lineage) or TukTuk (AI-generated framework) as observed by The DFIR Report TB40048 in May 2026.

## Why this discriminates

EtherRAT uses Ethereum smart contracts as C2 resolvers and TryCloudflare tunnels as ephemeral C2 endpoints. Legitimate Node.js developers occasionally launch portable Node from AppData, but they do not query `1rpc.io` in the same execution window. The two events together cross the false-positive floor.

## Query — KQL (Defender XDR)

```kql
let cfg_loads =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName =~ "node.exe" or FileName =~ "conhost.exe")
    | where ProcessCommandLine has "--headless"
       or ProcessCommandLine has @"\AppData\Local\"
    | where ProcessCommandLine has_any (".cfg", ".ini")
    | project Timestamp, DeviceId, DeviceName, ProcessCommandLine,
              InitiatingProcessFileName;
let c2_egress =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("1rpc.io", "arweave.net", "g8way.io", "trycloudflare.com")
    | project EgressTimestamp = Timestamp, DeviceId, RemoteUrl,
              InitiatingProcessFileName;
cfg_loads
| join kind=inner c2_egress on DeviceId
| where (EgressTimestamp - Timestamp) between (0min .. 5min)
```

## Expected benign

- Developers running custom Node tooling from a portable AppData install do not query `1rpc.io` or Arweave gateways.
- Electron applications that spawn node.exe from AppData do not load `.cfg` or `.ini` blobs with arbitrary names.

## Expected malicious

- Two-step chain: a `node.exe` or `conhost --headless` from a randomised AppData subpath loads a `.cfg`, and within five minutes the same host queries `1rpc.io` or hits a TryCloudflare URL not seen in the 30-day baseline.

## Action on match

1. Network-isolate the host at the switch or via EDR network containment — do not reboot.
2. Acquire RAM with `winpmem` before any other action. The `/api/reobf/` post-update code and TukTuk transport config only exist in memory.
3. Capture volatile artefacts (`tasklist`, `netstat`, copy Sysmon EVTX, copy Defender EDR logs).
4. Walk through the IR playbook in the parent `README.md`, sections "First 60 minutes (triage)" and "Containment, eradication, recovery".
