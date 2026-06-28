# PEAK Hunt H3 — ADB 0.0.0.0/loopback:5555 foothold on proxy exit nodes

**Hypothesis:** The Neunative relay's destination filter blocks RFC1918/loopback/link-local but
omits `0.0.0.0/8` (which maps to loopback on Linux/Android) and sets no port blocklist. A proxy
customer issuing `OpenTunnel("0.0.0.0", 5555)` reaches the exit device's own ADB daemon — turning
a proxy node into an initial-access foothold and botnet recruit. On the exit-node population,
connections targeting `0.0.0.0`/loopback on port 5555 should be visible.

**Framework:** PEAK.

## Prepare

- Scope: IoT / Android-TV / edge devices acting as proxy exit nodes (no host EDR); plus any
  endpoint network sensor that sees loopback/`0.0.0.0` targets.
- Data: network sensor flows, EDR network events, ADB service state on managed Android estate.

## Execute

1. Hunt for connections with destination port 5555 and target IP `0.0.0.0` or `127.0.0.1`
   (loopback), especially shortly after relay (port-6000) activity on the same device.
2. On managed Android/Android-TV, check `persist.adb.tcp.port` and whether ADB-over-TCP is on.
3. Correlate any inbound exploitation or loader fetch (e.g. Potassium/Gafgyt/IranBot hosts in
   the IOC list) following the ADB reach.

## Act with Knowledge

- True positive: disable ADB-over-TCP, block port 5555 at the perimeter, factory-reset
  compromised boxes, and treat the device as a botnet recruit until proven clean.
- Expected (benign): legitimate developer ADB debugging — scope this hunt to non-developer
  device groups.

## Notes

This is a destination-filter design gap, not a CVE; the fix is on the device (disable ADB-over-TCP)
and at the network edge (block 5555), since the SDK operator controls the relay, not the victim.
