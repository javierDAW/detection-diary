# PEAK Hunt H3 — Loader injection into npm CLI / Electron apps and credential staging

**Hypothesis.** On a developer workstation that imported a Joyfill `2773` build, the RAT persisted by patching the global npm CLI (`npm/lib/cli.js`) and Electron app modules (`@vscode/deviceid`, Discord core, GitHub Desktop `main.js`), and staged a Python credential stealer's encrypted archive under `%USERPROFILE%\.npm` or `/tmp/.npm`.

**Prepare (data).** Endpoint file telemetry (`DeviceFileEvents`, Sysmon EID 11) and the ability to read the suspect files. File-integrity monitoring on developer machines is the control that catches what registry scanning cannot.

**Execute (analytic).**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("npm\\lib\\cli.js","npm/lib/cli.js","@vscode\\deviceid","@vscode/deviceid","discord_desktop_core","GitHub Desktop\\resources\\app\\main.js")
   or FolderPath has_any ("\\.npm\\","/.npm/")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```

**Act.** On each target file, grep for the injected sentinel tags (`C250617A`, `C250618A`, `C250619A`, `C250620A`, `C260511A`, `C260512A`, `RS260605`) and the `9-0135-3` marker; the local YARA rule `Joyfill_npm_Loader_Injected_Block` confirms it. If found, reinstall the affected applications and the global npm, delete the staging archive, and rotate browser secrets, Git/GitHub tokens, npm tokens, SSH keys and any wallet keys present on the host.

**Notes / pitfalls.** Legitimate upgrades of npm/VS Code/Discord/GitHub Desktop rewrite these files — correlate with a matching updater process and a version change. The injected blocks are idempotent and guarded by the sentinel comments, so a second infection may leave the mtime unchanged; grep for the tag, do not rely on timestamps.

**Refine.** Deploy file-integrity monitoring on the four target paths across the dev fleet; add the sentinel tags as a content signature to your EDR and email/registry-scan pipeline.
