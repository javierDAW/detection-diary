# PEAK Hunt H2 — Proxy relay active while the VPN is idle/disconnected

**Hypothesis:** Neunative inverts normal VPN behavior — the exit-node relay runs while the
WireGuard tunnel is *down* (so it exits through the user's residential IP) and stops when the
tunnel comes up. A "VPN" process whose outbound relay activity *increases* while its tunnel
interface is inactive is proxyware whose on-state is the user's off-state.

**Framework:** PEAK.

## Prepare

- Scope: hosts running RoboVPN or any app embedding the Neunative SDK.
- Data: EDR network events, Windows service state (`RoboVPN_WG0` / `RoboVPN_WG`), interface/up-down
  telemetry where available.

## Execute

1. Identify hosts with the WireGuard service `RoboVPN_WG0`/`RoboVPN_WG` present.
2. Build a timeline of tunnel-up vs tunnel-down windows (service running / interface up).
3. Overlay outbound TLS to port 6000 and `/regdev` registration events.
4. Flag hosts where port-6000 relay activity concentrates in the tunnel-DOWN windows.

## Act with Knowledge

- True positive: the anti-correlation (relay active only when VPN is off) is itself the finding;
  treat as unauthorized resource hijacking. Remediate per the README playbook.
- Expected (benign): legitimate corporate VPNs do not run a third-party relay when disconnected.

## Notes

Account for the 30-90 minute random activation delay: relay traffic may begin well after the
tunnel drops, so widen the correlation window past the disconnect event.
