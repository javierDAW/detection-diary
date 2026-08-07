# PEAK Hunt H1 — An npm install spawned node setup.mjs and then a downloaded Bun runtime

**Hypothesis.** A trojanized package in the keyv/cacheable Shai-Hulud wave was installed in our build, CI or a developer session, so a `preinstall` hook ran `node setup.mjs`, which downloaded a standalone Bun 1.3.13 runtime into a `bun-dl-*` temp directory and executed the Stage-2 bundle (`Math_Symbol.js` / `math_init.js`) under `bun`.

**Prepare (data).** Endpoint process telemetry with command line and parent: Defender XDR `DeviceProcessEvents`, Sysmon EID 1, or auditd `execve`. Retain the `node` -> child process chain and CI job process trees.

**Execute (analytic).**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessCommandLine has "preinstall" and ProcessCommandLine has "setup.mjs")
    or (FileName in~ ("node.exe","node") and ProcessCommandLine has "setup.mjs")
    or (FileName in~ ("bun.exe","bun") and (ProcessCommandLine has "bun-dl-" or FolderPath has "bun-dl-"))
| summarize Hits=count(), Cmds=make_set(ProcessCommandLine,8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessFileName, AccountName
| order by LastSeen desc
```

**Act.** For each hit, pull the surrounding process tree and the project's lockfile. Grep lockfiles and `node_modules` for the affected package names and versions (`keyv@6.0.0`, the `cacheable`/`flat-cache`/`file-entry-cache`/`cache-manager` burst versions, `@thiennq/docs-viewer@1.6.2`), and for any package installed immediately before the `setup.mjs` execution. Treat the host as credential-exposed and hand off to H2 (persistence) before rotating anything.

**Notes / pitfalls.** A handful of legitimate projects ship a `setup.mjs` and use Bun; the discriminators are that Bun is run from a `bun-dl-*` temp directory it just downloaded, that the run clusters with an `npm install`, and that `Math_Symbol.js`/`math_init.js` appears alongside. `npm install --ignore-scripts` (and npm 12's default script blocking) prevents the `preinstall` path but NOT the `.claude`/`.vscode` repository-open path — hunt that in H2.

**Refine.** Promote confirmed project+host pairs to a scheduled analytic; feed resolved package versions into a registry-proxy blocklist and the lockfile-diff gate in CI.
