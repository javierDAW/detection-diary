# PEAK Hunt H2 — Injected Microsoft process beaconing to non-Microsoft infrastructure

**Author:** Jarmi
**Date:** 2026-06-15
**Case:** OceanLotus (APT32) SPECTRALVIPER (ESET)
**Type:** Hypothesis-driven (PEAK)

## Hypothesis

The SPECTRALVIPER loader injects the backdoor into `OneDrive.Sync.Service.exe`, which then beacons over HTTPS to attacker C2, hiding encrypted host-profiling data in an HTTP `Cookie` header (`zd_cs_pm=` / `euconsent-v2=`). If this occurred, a benign Microsoft binary made outbound connections to **non-Microsoft** infrastructure.

## ABLE framing

- **Actor:** OceanLotus / APT32.
- **Behaviour:** process injection (T1055) + web-protocol C2 with encrypted channel (T1071.001, T1573).
- **Location:** network-connection telemetry keyed on `OneDrive.Sync.Service.exe`; the Cookie header where TLS is inspected.
- **Evidence:** `DeviceNetworkEvents` (initiating process + remote host), Sysmon EID 3/22, proxy logs.

## Data sources

- Defender XDR `DeviceNetworkEvents`.
- Sysmon EID 3 (network connection), EID 22 (DNS), EID 8/10 (injection into OneDrive).
- Proxy/TLS-inspection logs (Cookie header, SNI).

## Query seed

See [../kql/oceanlotus_spectralviper_c2.kql](../kql/oceanlotus_spectralviper_c2.kql) and [../sigma/spectralviper_injected_onedrive_beacon.yml](../sigma/spectralviper_injected_onedrive_beacon.yml).

```kql
DeviceNetworkEvents
| where Timestamp > ago(45d)
| where InitiatingProcessFileName =~ "OneDrive.Sync.Service.exe"
| where RemoteUrl !has "microsoft" and RemoteUrl !has "onedrive" and RemoteUrl !has "live.com"
      and RemoteUrl !has "windows.net" and RemoteUrl !has "office.com"
| summarize count(), make_set(RemoteUrl,50), make_set(RemoteIP,50) by DeviceName
```

## Triage / pivots

1. Allow-list the Microsoft/OneDrive endpoints seen in your environment; investigate the remainder.
2. For surviving destinations, check for the C2 domains/IPs and the `apparatus/wind/twig/statement.html` beacon path.
3. Where TLS is inspected, hunt the `Cookie: zd_cs_pm=`/`euconsent-v2=` prefix.
4. Pivot to the host's side-loading pair (H1) and the injection events (EID 8/10) to confirm the chain.

## Outcome / ABLE close

- **Found:** capture OneDrive process memory (recover SPECTRALVIPER + RTTI), isolate, escalate.
- **Not found:** record injection-egress coverage; baseline OneDrive's legitimate destinations and alert on deviations.
