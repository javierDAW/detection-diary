# PEAK H2 — HKCU Run-key Microsoft Edge Update masquerade across the estate

## Hypothesis
Any managed Windows endpoint in our estate has, in its `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` hive, a value named `MicrosoftEdgeUpdate`, `EdgeApp`, or `MicrosoftEdge` whose target path is NOT inside the genuine Microsoft Edge install (`C:\Program Files (x86)\Microsoft\EdgeUpdate\`, `C:\Program Files\Microsoft\EdgeUpdate\`, `…\Microsoft\Edge\Application\`). This is the canonical UAC-0057 / Ghostwriter OYSTERSHUCK persistence anchor (CERT-UA#6315762, 22-May-2026) and has also been observed across multiple unrelated 2026 clusters that reuse the Edge-Update masquerade.

## Why this discriminates
The genuine Microsoft Edge auto-update mechanism registers itself under `HKLM` and Program Files, never under `HKCU`. Any `HKCU` value bearing one of these names is therefore highly anomalous before checking the path. The path check eliminates the residual edge-case of enterprise Edge deployments that use a non-default install location. False positives are near zero in unmanaged or single-tenant environments; in managed enterprise environments expect a small number of legitimate per-user Edge augmentations that are easy to whitelist by signer.

## Expected benign vs malicious
- Benign: enterprise endpoint-management tooling (Microsoft Intune, ConfigMgr) that registers a per-user Edge augmentation under HKCU with a signed binary path; verify signer.
- Benign: developer testing an Edge-related shim with HKCU registration; user accountable.
- Malicious: `HKCU` value pointing to `%APPDATA%\…\MicrosoftEdgeUpdate.exe` or `%LOCALAPPDATA%\…\EdgeApp.exe` (paths the genuine updater never uses) — high-confidence persistence anchor, escalate to host quarantine.

## Data sources
- Defender XDR — `DeviceRegistryEvents` (live + retroactive).
- Sysmon EID 12 (registry key create/delete) and EID 13 (registry value set) — `TargetObject` + `Details`.
- KAPE / RegRipper — offline collection from host triage for `NTUSER.DAT`.
- Autoruns (Sysinternals) — live snapshot per host; export CSV for cross-host correlation.

## Search logic (Defender XDR KQL)
See [`../kql/uac0057_run_key_edge_masquerade.kql`](../kql/uac0057_run_key_edge_masquerade.kql). For offline triage, run `RegRipper -r NTUSER.DAT -p run -u` per host and grep for `MicrosoftEdgeUpdate|EdgeApp|MicrosoftEdge` whose target path does not resolve to a Microsoft-signed Edge binary.

## Time window
90 days for the Defender XDR query (registry events have shorter retention than process events). For deep retroactive review, pull NTUSER.DAT snapshots from your backup tier and run RegRipper offline.

## Action on match
1. For every match, query `DeviceProcessEvents` for the timestamp of the registry write — identify the writing process. The genuine Edge updater is `MicrosoftEdgeUpdate.exe`; any other writer (`wscript.exe`, `powershell.exe`, `cmd.exe`, an extracted ZIP-archive helper) is malicious.
2. Quarantine the host (EDR isolate) and run the IR playbook from `README.md`.
3. Export the registry value contents to forensic storage before deletion — for OYSTERBLUES this may be the encrypted second-stage blob.
4. Search the entire estate for the same value across every HKCU hive — UAC-0057 sends the same lure to many recipients; a single positive should expand to a cross-host sweep.
5. Push the (sanitised) Run-key value path to the EDR custom-IOC pipeline so future drops are blocked at write time.

## Notes
- The masquerade family extends beyond Edge to Outlook (`OutlookUpdate.exe`), Teams (`TeamsUpdate.exe`), and OneDrive (`OneDriveUpdate.exe`) — apply the same path-discriminator pattern to all four name spaces if your environment shows a cluster of HKCU Run-key suspicions.
- The scheduled-task anchor (`MicrosoftEdgeUpdateTaskMachine` without `Core`/`UA` suffix) is the parallel persistence layer — combine both hunts for a single full-coverage sweep.
