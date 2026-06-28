# PEAK Hunt H1 — Neunative director registration followed by port-6000 relay

**Hypothesis:** If a host runs the Neunative residential-proxy SDK, its proxy/DNS telemetry will
show enrollment to the director `gmslb[.]net` via `/regdev?...sdkv=8.0.36...` with the literal
User-Agent `SDK`, followed within 30-90 minutes by repeated TLS connections to remote port 6000
against rotating `sN.<front>.com` hosts (`viki-play[.]com`, `star-layer[.]com`). This
register-then-relay shape is distinct from any browser.

**Framework:** PEAK (Prepare, Execute, Act with Knowledge).

## Prepare

- Scope: all managed Windows endpoints (and any network-visible IoT/Android-TV segment).
- Data: forward-proxy / TLS-inspection logs, DNS logs, EDR network events.
- Known-good: there is no expected enterprise use of `gmslb[.]net` or `/regdev` with UA `SDK`.

## Execute

1. Find director enrollment: web/proxy events where host contains `gmslb` OR URI contains
   `/regdev` AND query contains `sdkv=`, OR User-Agent equals the literal `SDK`.
2. For each matching source host, pivot to outbound TLS to remote port 6000 in the following
   90 minutes; count distinct remote hosts.
3. A host with both signals (registration + multi-host port-6000 relay) is high-confidence
   proxyware.

## Act with Knowledge

- True positive: isolate, uninstall the embedding app, remove `HKCU\Software\Neunative`, block
  the director domain. Pivot on the director + port-6000 set to find the rest of the fleet.
- Expected (benign): none in a managed environment.
- Promote signals 1+2 to the Sigma/KQL detections in this folder; add the director domain to
  DNS sinkhole.

## Notes

The relay fleet (~360 hosts) rotates and IP blocking ages out fast; the durable anchors are the
director domain, the `/regdev` path, the UA `SDK`, and the port-6000 behavior.
