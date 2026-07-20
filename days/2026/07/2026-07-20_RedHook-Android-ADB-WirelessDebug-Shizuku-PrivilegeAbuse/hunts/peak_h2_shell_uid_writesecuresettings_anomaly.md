# PEAK Hunt H2 -- Non-system app holding shell UID (2000) or an unexplained WRITE_SECURE_SETTINGS grant

**Hypothesis.** A non-system, non-power-user-installed Android app has a process
associated with shell UID 2000, or has been granted `WRITE_SECURE_SETTINGS`,
outside any known MDM/EMM or Shizuku-consumer workflow. This is the state RedHook
reaches once its bundled Shizuku-derived server (`libmx.so`) is running under the
borrowed shell identity after autonomous ADB Wireless Debugging pairing.

**Why it works.** Shell UID (2000) and `WRITE_SECURE_SETTINGS` are significantly
more privileged than an ordinary app's sandbox and are normally reserved for ADB
itself or a deliberately-installed Shizuku consumer app. An unrecognised package
holding either is anomalous on a stock, non-power-user Android fleet.

## Data sources
- MTD / Defender for Endpoint mobile: process-uid telemetry, permission-grant
  events (`WRITE_SECURE_SETTINGS`).
- `DeviceEvents` (process creation with uid metadata, permission grants).
- MDM app catalogue (to derive the approved Shizuku-consumer package allow-list).

## Analytic steps
1. Enumerate processes associated with shell UID 2000 across the managed fleet,
   and separately enumerate `WRITE_SECURE_SETTINGS` grant events.
2. Subtract system packages (`com.android.*`, `com.google.android.*`) and the
   approved Shizuku/ADB power-user package set.
3. For each remaining match, correlate against H1 (a recent Accessibility-to-
   ADB-enable chain on the same device) to raise confidence.
4. Pull the package's installer source and recent network destinations; a
   sideloaded installer plus egress to the `3n7wj[.]com` domain family confirms
   the RedHook hypothesis specifically.

## Expected benign
A deliberately-installed Shizuku consumer app (e.g. a legitimate ad-blocker or
system-tweak tool a power user set up on their own device) will hold this
capability by design; baseline and allow-list that small set.

## Pivots / escalation
Confirmed shell-uid capability or `WRITE_SECURE_SETTINGS` by an unrecognised
package is a high-confidence active compromise: treat screen content, keystrokes,
SMS, and contacts as exposed, and begin the IR playbook's first-60-minutes
triage immediately.

Linked detections: `sigma/android_shell_uid_privileged_process_non_system_app.yml`,
`kql/redhook_privileged_shell_uid_anomaly.kql`.
