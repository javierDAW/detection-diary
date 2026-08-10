# PEAK Hunt H1 - Malware download following a captive-portal connectivity check

## Hypothesis
On a network served by a compromised captive portal, Storm-2945 manipulates DNS and HTTP so
that the automatic connectivity check a browser or OS issues on join (NCSI / captive-portal
probe) is answered with a fake "browser or operating system update" ClickFix page. If this is
happening in our estate, we expect to see an executable/installer file created on a host within
a short window after that host queried a known connectivity-check endpoint, on a foreign or
hospitality network.

## Rationale (ABLE)
- **Actor behaviour:** traffic manipulation on captive portals since early May 2026; malware is
  "purporting to be browser or operating system updates in response to automated connectivity
  checks issued by users' browsers."
- **Analytic value:** the connectivity-check -> file-write sequence is a durable behavioural
  anchor that survives infrastructure rotation, unlike the specific doppelganger domains.

## Data sources
- Defender XDR: `DeviceNetworkEvents` (connectivity-check endpoints), `DeviceFileEvents`
  (FileCreated of .exe/.msi/.zip/.rar/.7z/.apk).

## Query logic
1. Collect `DeviceNetworkEvents` where `RemoteUrl` matches an NCSI/captive-portal endpoint
   (msftconnecttest.com, detectportal.firefox.com, captive.apple.com, connectivitycheck.gstatic.com, etc.).
2. Join to `DeviceFileEvents` `FileCreated` of an executable/archive on the same `DeviceId`.
3. Keep pairs where the download timestamp is within 2 minutes after the connectivity check.

## Triage / expected vs benign
- **Malicious:** installer named like a browser/OS update, written to Downloads/Temp, on a host
  that just joined a hotel/conference SSID; followed by a child process from an AppData path.
- **Benign:** genuine browser auto-update pipelines (these do not follow a user-visible ClickFix
  page and write to Program Files / update staging dirs, not user Downloads).

## Pivots on a hit
- Look for a `svchost32.exe` process/service (CornFlake) and for outbound to the CaptiveCrunch
  IOC set; check the user's Entra sign-ins for a device code authentication around the same time.
