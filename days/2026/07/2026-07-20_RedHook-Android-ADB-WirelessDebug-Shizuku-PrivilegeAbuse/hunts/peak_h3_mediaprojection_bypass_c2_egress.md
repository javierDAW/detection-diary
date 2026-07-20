# PEAK Hunt H3 -- Screen-streaming network activity without a MediaProjection consent event, plus C2 egress

**Hypothesis.** A device shows sustained outbound WebSocket- or RTMP-pattern
network activity to an unfamiliar domain with no corresponding `MediaProjection`
consent-dialog event in the same session, especially when paired with egress to
the `3n7wj[.]com` domain family. RedHook streams the screen over RTMP directly
from its shell-privileged process, which bypasses the mandatory `MediaProjection`
API and its consent dialog entirely.

**Why it works.** Legitimate screen-mirroring, remote-support, and streaming
apps trigger the `MediaProjection` consent dialog by design; its absence during
sustained streaming-pattern network activity is anomalous and, combined with
egress to a known RedHook C2 domain, is high-confidence.

## Data sources
- MTD / Defender for Endpoint mobile: network-flow telemetry (`DeviceNetworkEvents`),
  `MediaProjection` consent-dialog events (where the MTD vendor surfaces this).
- Network egress logs / proxy for the `3n7wj[.]com` domain family and RTMP-pattern
  traffic (TCP 1935 or WebSocket-over-443 with streaming byte-rate characteristics).

## Analytic steps
1. Identify devices with sustained outbound streaming-pattern network flows
   (WebSocket or RTMP) to domains outside the approved remote-support/streaming
   app allow-list.
2. Check for a corresponding `MediaProjection` consent event on the same device
   in the same session window; flag flows with no matching consent event.
3. Cross-reference against the `3n7wj[.]com` domain family specifically for a
   direct RedHook match; treat non-matching unfamiliar domains as a broader hunt
   lead for other screen-streaming malware.
4. Correlate with H1 and H2 (Accessibility-to-ADB chain, shell-uid anomaly) on
   the same device to build full-chain confidence before triage.

## Expected benign
Legitimate remote-support and screen-mirroring tools that correctly trigger
`MediaProjection` consent, or that the MTD vendor does not yet correlate --
tune the join window and confirm vendor event coverage before trusting a
negative result.

## Pivots / escalation
Confirmed streaming egress with no consent event, especially to `3n7wj[.]com`,
means screen content and any credentials entered during the session should be
treated as exposed; begin the IR playbook's first-60-minutes triage and force
credential resets through a trusted separate channel.

Linked detections: `sigma/android_mediaprojection_bypass_screen_stream.yml`,
`kql/redhook_c2_websocket_rest_network.kql`.
