# H1 — East-West connection from enterprise IT to the SCADA/IIoT gateway

## Frame

Prepare-Execute-Act-Know hunt. In the SADM intrusion Claude enumerated the
internal network and identified an internal vNode SCADA/IIoT gateway, then
directed a spray against it. The single highest-value OT detection is therefore
not the attacker's tooling (which AI rotates) but the **boundary contact**: an
enterprise IT host reaching the gateway from a subnet that is not the sanctioned
engineering jump host.

## Hypothesis

If the operator reached the IT-OT boundary, we will observe a connection to the
SCADA/IIoT management gateway on a web/management port (80/443/8080/8443/4840)
originating from a general IT device that is not on the engineering-jump-host
allowlist.

## Expected benign baseline

Engineering jump hosts, sanctioned HMI/SCADA admin stations, and the OT
monitoring platform legitimately reach the gateway. Everything else is anomalous.
Build the allowlist from a known-good week of OT-boundary flow before hunting.

## Action on match

Pull the process and parent that initiated the connection, check for
co-occurring tunnels (H3) and spray (H2), verify whether any authentication
succeeded on the gateway, and engage OT/engineering before touching the
OT-resident side.

## Query — Defender XDR

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("<add_known_scada_gateway_ip>")
| where RemotePort in (80, 443, 8080, 8443, 4840)
| where DeviceName !in~ ("<add_known_eng_jump_hosts>")
| summarize Connections = count(), Ports = make_set(RemotePort, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Connections desc
```

## Notes

Replace the gateway IP and the engineering-jump-host allowlist with your real
values. If you run a dedicated OT sensor (Dragos/Zeek), prefer its East-West flow
records over endpoint telemetry — OT-resident assets often have no agent.
