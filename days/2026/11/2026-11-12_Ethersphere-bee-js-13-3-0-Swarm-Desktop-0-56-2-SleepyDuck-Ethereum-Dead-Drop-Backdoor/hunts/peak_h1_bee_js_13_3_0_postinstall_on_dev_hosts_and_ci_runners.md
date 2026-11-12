# PEAK hunt H1 - Did any developer host or CI runner install @ethersphere/bee-js 13.3.0 and run its postinstall loader?

## Prepare

- **Hypothesis:** at least one developer workstation, build server or CI runner resolved `@ethersphere/bee-js@13.3.0` (directly or transitively) between 2026-11-09 00:09:50 and 01:24:58 UTC, or later from a cache / internal mirror, and its package manager executed the dependency lifecycle script `postinstall: node scripts/generate-version.cjs`, which reached `api.frameworkmetrics.xyz/v1/analytics` and executed whatever came back.
- **Why:** Socket and StepSecurity (2026-11-09) report that 13.3.0 was published through GitHub trusted publishing with valid SLSA provenance after an unsigned direct commit (`de2f74e784b2eafa0d66fbb6d88b42ea11ee34cf`, identity `bee-worker`). The release renamed `prepare` to `postinstall` and added `scripts` to the published `files`. The loader sends `User-Agent: <process.platform>` and `X-Ethersphere: 1`, waits up to 3000 ms and runs the body with `new Function('require','console','process',body)`. Stage 2 steals Swarm `config.yaml` and `data-dir/keys/swarm.key`; stage 3 installs a Go backdoor (Linux / macOS) or ScreenConnect (Windows). npm 11 and earlier, Yarn Classic and Yarn Berry < 4.14.0 run dependency `postinstall` by default.
- **Honesty:** valid provenance does NOT mean a safe package here - the build pipeline itself was abused. The stage-2 JavaScript source, infection counts and whether funds were stolen are not published. A timeout of the C2 call means nothing ran; a 200 response means the host must be treated as compromised.
- **Scope:** all repositories with a lockfile, all CI providers (GitHub Actions, GitLab, Jenkins, Azure Pipelines), internal npm mirrors / proxies (Artifactory, Verdaccio, Nexus) and developer endpoints; 2026-11-09 onwards.
- **Confidence:** high for lockfile + loader execution + egress; medium for "install inside the window" alone.

## Execute

**Data sources / content:** lockfiles, CI job logs, internal registry access logs, `kql/k3_npm_install_exposure_window_and_swarm_desktop_0_56_2_inventory.kql`, `kql/k1_frameworkmetrics_egress_hub_ips_and_solidity_eth_rpc_dead_drop.kql`, `sigma/01_bee_js_swarm_loader_connection_to_frameworkmetrics.yml`, `sigma/04_dns_query_frameworkmetrics_xyz.yml`, `yara/bee_js_swarm_sleepyduck.yar` (rule `BeeJs_Swarm_FrameworkMetrics_Loader_JS`).

1. Find the version in every lockfile (read-only):

```bash
# Author: Jarmi
# package-lock.json / npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml
grep -RIn --include=package-lock.json --include=npm-shrinkwrap.json -A2 '"node_modules/@ethersphere/bee-js"' . | grep -n '"version": "13.3.0"'
grep -RIn --include=yarn.lock -A1 '^"\?@ethersphere/bee-js@' . | grep 'version "13.3.0"'
grep -RIn --include=pnpm-lock.yaml '@ethersphere/bee-js@13.3.0' .
# Any installed copy on disk (dev hosts, runner caches, container layers)
find / -path '*/node_modules/@ethersphere/bee-js/package.json' 2>/dev/null -exec grep -l '"version": "13.3.0"' {} +
```

2. Grep CI logs and npm debug logs for the loader banner and the script name:

```bash
# Author: Jarmi
grep -RIn -e '\[FrameworkMetrics\] analytics v2.3.1 is up to date' -e 'scripts/generate-version.cjs' ~/.npm/_logs/ ./ci-logs/ 2>/dev/null
# GitHub Actions: download logs for runs in the window and search
gh run list --repo <org>/<repo> --created '2026-11-09' --json databaseId,createdAt,name --jq '.[] | [.databaseId,.createdAt,.name] | @tsv'
gh run view <run_id> --repo <org>/<repo> --log | grep -n -e 'FrameworkMetrics' -e 'generate-version.cjs'
```

3. Hash the loader where a copy exists; the malicious `scripts/generate-version.cjs` is `ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f`, and scan it with the YARA rule.

```bash
# Author: Jarmi
find / -path '*/@ethersphere/bee-js/scripts/generate-version.cjs' 2>/dev/null -exec sha256sum {} +
yara -r yara/bee_js_swarm_sleepyduck.yar /path/to/node_modules/@ethersphere/
```

4. Check internal registry / proxy logs for downloads of `bee-js-13.3.0.tgz` and for any client that later fetched it from cache.
5. Correlate with DNS / proxy egress to `frameworkmetrics.xyz` from the node process or the runner (k1, Sigma 01 / 04). Ephemeral GitHub-hosted runners leave no endpoint telemetry - rely on job logs and on what secrets the job had.

## Act

- **Expected benign:** installs inside the window that resolved an older bee-js version (most hits of k3 branch 1); maintainers building bee-js from source (where `generate-version.cjs` is a legitimate `prepare` step without network egress); `npm ci --ignore-scripts` builds that never executed lifecycle scripts.
- **Action on match:** lockfile 13.3.0 + loader banner or egress = compromised host. Isolate, image, then pivot to H2 (Linux / macOS backdoor) or the Windows stage (k2, Sigma 03). Treat every secret available to the process as exposed: npm / GitHub tokens, cloud credentials, SSH keys, wallet keys and Swarm `swarm.key` / `config.yaml`. Rotate from a clean host, move the wallet funds to a fresh key, pin `@ethersphere/bee-js` to a clean version and purge the tarball from internal mirrors and caches.
- **Escalation:** ephemeral CI runner hits -> list the job's secrets and their scopes and rotate all of them; self-hosted runner hits -> treat as a persistent foothold (H2).
- **Detections:** keep Sigma 01 / 04 and Suricata 9992001 / 9992002 as alerts; enforce `ignore-scripts=true` in `.npmrc` for CI, or move to npm >= 12 / Yarn Berry >= 4.14.0 behaviour where dependency scripts need opt-in; add a minimum release age (cooldown) on the internal mirror.
- **Exit criteria:** no lockfile in the estate references 13.3.0; no cached tarball remains; every exposed credential rotated; no further egress to the domain or hub IPs.
