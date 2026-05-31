# H3 — Proxied RDP arrival + Go tunneler beacon

## Frame

Prepare-Execute-Act-Know hunt. Gambit reconstructed proxied RDP into SFRTA via
`proxychains` + `xfreerdp` relayed through 91.193.19.198:8443, with a customized Go
tunneler (A.ExE) providing C2. The access pattern co-occurs with the destruction.

## Hypothesis

If proxied access was used, a host shows an interactive RDP logon arriving via a
multi-hop relay and/or a Go-tunneler beacon to the Black Shadow C2/infra IPs within
the same window as management-console activity.

## Expected benign baseline

Admin RDP comes from known jump hosts/subnets. Proxychains-fronted RDP, or egress
to the tunneler infra IPs, is anomalous in most estates.

## Action on match

Isolate the host, capture the tunneler binary for the YARA rule, map the relay
chain, and check the host for subsequent vCenter/SSMS/Veeam console use (H1/H2).

## Query — Defender XDR (RDP logon + tunneler egress)

```kql
let beacon =
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "nefeshhope.com" or RemoteIP in ("46.30.190.173","45.150.108.61","91.193.19.198","31.172.87.20")
    | distinct DeviceName;
DeviceLogonEvents
| where Timestamp > ago(30d)
| where LogonType == "RemoteInteractive"
| where DeviceName in (beacon)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
| order by Timestamp desc
```

## Notes

On the attacker/Linux jump side, hunt `proxychains` wrapping `xfreerdp` directly
(Sigma 03). The relay IP/port (91.193.19.198:8443) is a high-value pivot.
