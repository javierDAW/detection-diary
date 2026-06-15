# PEAK Hunt H3 — Third-party software updaters fetching insecure updates

**Author:** Jarmi
**Date:** 2026-06-15
**Case:** OceanLotus (APT32) SPECTRALVIPER — FireAnt MetaKit supply chain (ESET)
**Type:** Hypothesis-driven (PEAK)

## Hypothesis

OceanLotus shipped SPECTRALVIPER by replacing the legitimate `setup.exe` on the FireAnt MetaKit update server, which served updates over **cleartext HTTP with no integrity validation and no TLS**. If similar weak update channels exist in our estate, third-party updaters are fetching binaries over plain HTTP or without signature validation — a delivery surface an attacker can hijack the same way.

## ABLE framing

- **Actor:** OceanLotus / APT32 (and, generally, any supply-chain adversary).
- **Behaviour:** compromise software supply chain (T1195.002) + ingress tool transfer (T1105).
- **Location:** network egress from updater processes; proxy/HTTP logs; the `metakit.fireant.vn` host and the `V1/Update/GetUpdate` API.
- **Evidence:** `DeviceNetworkEvents` (HTTP fetches by updater processes), proxy logs, software inventory.

## Data sources

- Defender XDR `DeviceNetworkEvents`, `DeviceProcessEvents`.
- Proxy / web-gateway logs (HTTP vs HTTPS by destination).
- Software inventory (which updaters run, and how they validate updates).

## Query seed

See [../kql/oceanlotus_fireant_supplychain.kql](../kql/oceanlotus_fireant_supplychain.kql).

```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl startswith "http://"        // cleartext update fetches
| where InitiatingProcessFileName has_any ("update","setup","installer","metakit")
| summarize count(), make_set(RemoteUrl,50) by DeviceName, InitiatingProcessFileName
```

## Triage / pivots

1. Flag any host that fetched a MetaKit update from `metakit.fireant.vn` in the campaign window (2025-10-02 → 2026-03-09) — candidate supply-chain victims.
2. Search for the `V1/Update/GetUpdate` API and `/Software/setup.exe` / `/Software/version.xml` paths.
3. For each cleartext-HTTP updater, verify whether it enforces signature validation; treat those that do not as exposed delivery channels.
4. Correlate updater fetches with subsequent side-loading (H1) and injection (H2) on the same host.

## Outcome / ABLE close

- **Found (malicious):** isolate, capture the downloaded payload, escalate; notify the affected vendor and CERT.
- **Found (weak channel, no compromise):** raise a hardening action — enforce HTTPS + signature validation at the proxy; alert on cleartext-HTTP update fetches.
- **Not found:** record update-integrity coverage and baseline approved updater destinations.
