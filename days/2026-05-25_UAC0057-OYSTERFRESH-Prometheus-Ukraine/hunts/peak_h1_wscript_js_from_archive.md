# PEAK H1 — wscript.exe executing a .js file from an archive-extraction path in the last 90 days

## Hypothesis
In the 90 days preceding the CERT-UA OYSTERFRESH advisory (#6315762, 22-May-2026), at least one managed Windows endpoint in our estate executed `wscript.exe` with a `.js` file argument sourced from a user-writable archive-extraction path (`%TEMP%`, `%APPDATA%`, `Desktop`, `Downloads`, `C:\Users\Public\`). UAC-0057 / Ghostwriter has been running this chain against Ukrainian government targets since the spring of 2026 and uses compromised partner-tenant mailboxes for delivery, so any organisation with Ukrainian or Eastern-European business correspondence is in scope.

## Why this discriminates
The legacy Windows Script Host (`wscript.exe`) executing a `.js` from a user-writable path is extremely rare in modern enterprise endpoints — most legitimate JS execution happens inside browsers (Chrome / Edge), inside Node.js workflows on developer hosts, or via signed installer scaffolding (very short-lived). A persistent `wscript.exe` + `.js` from `Downloads` or an archive temp path is therefore high-fidelity by base rate. The discriminator survives loader rotation: even when OYSTERFRESH is replaced by a different JS payload, the wscript+js+archive-path pattern persists.

## Expected benign vs malicious
- Benign: developer running a `.js` helper via wscript for legacy automation (e.g. printer-driver scripted install); short-lived; signed parent; known developer host.
- Benign: software installer dropping a `.js` stub from `%TEMP%` during MSI execution; correlate with installer image + signer.
- Malicious: `.js` from `Downloads` or a user archive temp, parent `explorer.exe` / `outlook.exe` / `winrar.exe` / `7zfm.exe`, followed within 5 minutes by HTTP egress to a `.icu` FQDN; especially malicious if the user reports having opened an email attachment that day.

## Data sources
- Defender XDR — `DeviceProcessEvents` (process tree + command line).
- Sysmon EID 1 (process creation) — Image + CommandLine + ParentImage.
- Sysmon EID 11 (file create) — `.js` files written under user paths.
- EDR (CrowdStrike Falcon `ProcessRollup`, Sentinel One `Behavioral Indicators`).

## Search logic (Defender XDR KQL)
See [`../kql/uac0057_wscript_js_from_archive_post_to_icu.kql`](../kql/uac0057_wscript_js_from_archive_post_to_icu.kql). For pure-process hunting (no network correlation), run the first half of that query against `DeviceProcessEvents` alone over a 90-day lookback.

## Time window
90 days retroactive from today (2026-05-25). Extend to 180 days for organisations with continuous Eastern-European business correspondence.

## Action on match
1. For every match, pull the email gateway message-trace for the user mailbox in the 24 hours preceding the `wscript.exe` execution. Identify the originating email and the ZIP attachment.
2. Quarantine the user mailbox if the originating email is from a compromised partner-tenant; alert the partner organisation.
3. Snapshot RAM on the executing host before reboot. OYSTERBLUES decrypted form lives only in memory.
4. Pull the persistence anchors (HKCU Run keys, scheduled tasks) per the IR playbook.
5. Push the `.icu` FQDN (when extracted) to DNS sinkhole + IDS; push the originating email sender to the email gateway block list.
6. Cross-reference the user identity against Day 23 Storm-2949 cloud control-plane signals if the same user has any Azure / M365 admin role — UAC-0057 has not been observed pivoting to cloud control plane to date, but the dwell-time window is sufficient for credential theft regardless.

## Notes
- Pair this hunt with H3 (`.icu` POST cadence) to upgrade a single-process detection to a full kill-chain confirmation.
- Sandbox the recovered `.js` against the YARA rule in [`../yara/uac0057_oysterfresh_js_loader.yar`](../yara/uac0057_oysterfresh_js_loader.yar) before mass-deletion — preserve forensic value of the decoded next stage.
