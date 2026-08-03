# PEAK Hunt H3 - OctLurk/LurkProxy C2 Beacon and Masqueraded Tooling

- Author: Jarmi
- Date: 2026-08-03
- Frame: PEAK
- MITRE: T1071.001 (Web C2), T1090 (Proxy), T1571 (Non-Standard Port), T1003.006, T1555.003

## Hypothesis
A compromised host beacons to the OctLurk C2 `dns.multitoconference[.]com` over a raw TCP/443
stream socket (not TLS-wrapped HTTP), or tunnels through LurkProxy to `154.196.162[.]76:64980`,
and runs masqueraded post-exploitation tools: `Adobe.exe` (Impacket secretsdump / DCSync-style),
`64.exe` (browser password decryptor), `AnyDesk.exe` (keylogger), `fc.exe` (Fscan scanning SSH
22 / MySQL 3306 with `pp.txt`).

## Data sources
- Defender XDR `DeviceNetworkEvents` (remote IP/URL/port), `DeviceProcessEvents` (tool names +
  paths), `DeviceFileEvents` (msect\dev0/dev1, result.txt, info.txt, <host>.datb).
- NetFlow / Zeek conn+ssl (443 flows with no TLS ClientHello = raw socket), Suricata sids
  2026080301-2026080306.

## Execute
1. Surface egress to the C2 domains/IP and to TCP 64980; for 443 flows, separate true TLS from
   raw stream sockets (absent ClientHello) - the latter is the OctLurk tell.
2. Correlate the beaconing process with masqueraded tool executions from Users\...\Libraries and
   Users\Public\Pictures; flag secretsdump against a DC (EID 4662 replication rights, see repo
   Certighost hunt) and browser Login Data / logins.json access.
3. Time-line keylogger stores (msect\dev0/dev1) and archive staging (WinRAR/7-Zip) as
   collection/exfil precursors.

## Act
- True positive: isolate, block C2 (after revalidation - indicators decay), rotate domain-admin
  and krbtgt, collect memory. False positive: real AnyDesk/Adobe run from Program Files and are
  signed; the malicious copies run from user paths.

## Notes
Linked KQL: octlurk_lurkproxy_c2_network.kql, octlurk_masqueraded_tooling_in_libraries.kql.
