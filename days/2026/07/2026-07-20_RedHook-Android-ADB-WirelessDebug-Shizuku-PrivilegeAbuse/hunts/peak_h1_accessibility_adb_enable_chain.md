# PEAK Hunt H1 -- Accessibility grant followed by an autonomous Developer-Options / Wireless-ADB enable chain

**Hypothesis.** An Android app was granted the Accessibility service and, within
a short window and with no corresponding IT- or user-initiated developer action,
Developer Options and Wireless ADB (Wireless Debugging) became enabled and paired
on the same device. RedHook (Group-IB, 2026-07-09) automates exactly this chain
via Accessibility-driven UI taps to reach an autonomous, on-device, shell-level
privilege (uid 2000) without root or any exploit.

**Why it works.** Developer Options and Wireless ADB are legitimately enabled
directly by a developer or power user, not as a side effect of an unrelated
app's Accessibility grant. The chain -- Accessibility grant, then Developer
Options toggle, then Wireless-ADB enable, then pairing completed -- within
minutes on the same device, is the anomaly; any single event in isolation is
common and benign.

## Data sources
- MTD / Defender for Endpoint mobile: Accessibility service grant events,
  Developer Options / Wireless Debugging state-change events, ADB pairing
  completion events.
- `DeviceEvents` (Accessibility grants, settings state changes).
- MDM app catalogue (to derive the small legitimate Shizuku/ADB power-user
  package allow-list).

## Analytic steps
1. Enumerate Accessibility service grant events across the managed fleet.
2. For each grant, look for a Developer-Options-enabled, Wireless-Debugging-
   enabled, or ADB-pairing-completed event on the same device within 15 minutes.
3. Subtract devices where the granting package is a known, approved Shizuku or
   ADB power-user tool (e.g. `moe.shizuku.privileged.api`) deliberately installed
   by the device owner.
4. For remaining matches, pull the granting package's installer source -- a
   sideloaded source (unknown, filemanager, browser, package_installer, or null)
   raises confidence further.
5. Where the APK is recoverable, decode it (`apktool d`) and check for `libmx.so`,
   the `3n7wj[.]com` domain family, or the REST endpoint paths (Sigma + YARA in
   this folder).

## Expected benign
Developers and power users deliberately enabling Wireless ADB for Shizuku or
direct debugging; baseline and allow-list this small, known package set.

## Pivots / escalation
An unexplained Accessibility-to-ADB-enable chain by an unrecognised package is a
high-confidence RedHook (or similar) infection: pivot to H2 (shell-uid anomaly)
and H3 (MediaProjection-bypass streaming plus C2 egress), isolate the device via
MDM, and begin the first-60-minutes triage in the IR playbook.

Linked detections: `sigma/android_wireless_adb_autoenable_accessibility.yml`,
`kql/redhook_accessibility_adb_enable_chain.kql`.
