# PEAK Hunt H1 - Chromium launched headless with a remote debugging port

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1528 Steal Application Access Token; T1550.001 Use Alternate Authentication Material: Application Access Token.

## Hypothesis
An adversary is driving a Chromium-based browser (chrome.exe / msedge.exe) in headless mode over the
DevTools protocol to ride a live authenticated Google session and mint an OAuth authorization code
(ToddyCat's Shadow Token via Remote Debug, STRD). The browser is launched with both
`--remote-debugging-port` and `--headless`, typically against a copied profile in a `BackupFiles`
directory. On a standard user workstation this is anomalous by construction - interactive users do
not open a browser with a debug port.

## Prepare - data sources
- Defender XDR `DeviceProcessEvents`; Sysmon EID 1 (process creation with full command line).
- EDR parent-process lineage (was the browser spawned by explorer.exe, or by a signed loader?).
- File telemetry for `%LOCALAPPDATA%\Google\Chrome\BackupFiles` and `...\Microsoft\Edge\BackupFiles`.

## Execute - logic
1. Find every browser process whose command line contains both `--remote-debugging-port` and
   `--headless` - see `kql/umbrij_headless_remote_debug.kql` and
   `sigma/umbrij_browser_remote_debug_headless.yml`.
2. Flag those whose `--user-data-dir` points at a `BackupFiles` path, or whose parent is not
   explorer.exe (a signed loader in `\Users\Public`, `\Windows\Temp` or `\Windows\Vss` is high signal).
3. Subtract known automation hosts (CI runners, test rigs, print-to-PDF services) from the results.
4. For each remaining hit, pull the surrounding process tree and check for a preceding DLL sideload
   (H2) and a following OAuth grant to GWMMO/GWSMO (H3).

## Act - triage
- **Confirmed:** headless browser with a debug port, `--user-data-dir` on a copied profile, spawned by
  a non-explorer signed loader, on a workstation with no automation role. Isolate the host and revoke
  OAuth grants (see H3).
- **Escalation:** the same host also shows a masquerading `KasperskyEndpointSecurityEDRAvp` task or a
  sideloaded `log.dll` / `GoogleServices.DLL`.
- **Benign:** a developer or a known automation host driving Selenium/Puppeteer/Playwright; confirm the
  device role and the launching account.

## Knowledge - notes
STRD sidesteps DPAPI and cookie decryption entirely - it never cracks stored credentials, it borrows
the *live* session. Detection therefore lives at the launch (unusual browser flags) and at the grant
(unexpected OAuth app), not at a credential store. Record which hosts legitimately run headless
browsers so the signal stays high-fidelity.
