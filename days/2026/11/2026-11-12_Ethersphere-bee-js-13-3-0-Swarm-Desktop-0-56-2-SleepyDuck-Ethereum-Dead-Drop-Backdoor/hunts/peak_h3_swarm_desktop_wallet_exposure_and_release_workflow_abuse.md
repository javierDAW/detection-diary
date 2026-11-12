# PEAK hunt H3 - Swarm Desktop 0.56.2 wallet-file exposure and abuse of signing / release workflows (our own repos as the next victim)

## Prepare

- **Hypothesis (a - consumer side):** a host auto-updated to the malicious Swarm Desktop 0.56.2 (Windows x64 / Apple Silicon, about 00:43 to 09:14 UTC on 2026-11-09) and the loader in `app.asar` (`dist/desktop/src/index.js`, `/v1/electron`) posted the Swarm `config.yaml` and `data-dir/keys/swarm.key` (JSON fields `configYaml` and `v3`) to `https://api.frameworkmetrics.xyz/v1/swarm/report`, exposing the node wallet.
- **Hypothesis (b - producer side):** an attacker holding a maintainer or bot identity in one of our GitHub organisations can push unsigned commits directly to a release branch, publish a release without a pull request, trigger `workflow_dispatch` on a free-form branch to reach signing certificates or trusted-publishing tokens, or run workflows that dump `${{ toJSON(secrets) }}` to an external collector - exactly the sequence used against the Ethersphere repositories.
- **Why:** Socket and StepSecurity (2026-11-08/09): an unsigned direct commit `de2f74e7...` by `bee-worker` at 23:59:54 UTC, release v13.3.0 at 00:06:01 UTC, npm publish through trusted publishing at 00:09:50 UTC; Swarm Desktop 0.56.2 built by the manually triggered `pre-release.yml` with signing certificates (macOS signed "Developer ID Application: Swarm Association (9J9SPHU9RP)" and notarized). A failed attempt on 2026-11-06 used workflows dumping secrets to `webhook.site` from branches `probe/force-dryrun-*`, `security/lab-secrets-*` and `test-run`.
- **Honesty:** how the `bee-worker` credentials were obtained is not published; neither is the number of affected Swarm Desktop users or whether funds were stolen. Code signing and notarisation were valid - they prove the pipeline ran, not that the code was benign.
- **Scope:** (a) all endpoints running Swarm Desktop; (b) GitHub audit log for every organisation that publishes packages or signed binaries; 2026-10-01 onwards.
- **Confidence:** high for 0.56.2 presence or `bee-desktop.log` version line; medium for workflow-abuse patterns in our own orgs (patterns, not indicators).

## Execute

**Data sources / content:** `kql/k3_npm_install_exposure_window_and_swarm_desktop_0_56_2_inventory.kql` (branch `SwarmDesktop_*`), `kql/k1_frameworkmetrics_egress_hub_ips_and_solidity_eth_rpc_dead_drop.kql`, Swarm Desktop logs, GitHub audit log and Actions run history.

1. Consumer side - find the version and the exposure:

```bash
# Author: Jarmi
# Search the Swarm Desktop log for the malicious version line (log location depends on OS / install)
grep -RIn 'Bee Desktop version: 0.56.2 (production)' ~ 2>/dev/null --include='bee-desktop.log'
# Wallet files the stage 2 reads - if 0.56.2 ran, treat them as stolen
find ~ -path '*data-dir/keys/swarm.key' 2>/dev/null; find ~ -name config.yaml -path '*[Ss]warm*' 2>/dev/null
```

   On Windows, search `bee-desktop.log` with `Get-ChildItem $env:USERPROFILE -Recurse -Filter bee-desktop.log -ErrorAction SilentlyContinue | Select-String 'Bee Desktop version: 0.56.2'`. Clean baseline is 0.56.1.
2. Producer side - GitHub audit log patterns (read-only):

```bash
# Author: Jarmi
ORG=<your_org>
# Releases published and workflows dispatched by bot / service identities
gh api --paginate "/orgs/$ORG/audit-log?phrase=action:release.publish&per_page=100" --jq '.[] | [."@timestamp", .actor, .repo] | @tsv'
gh api --paginate "/orgs/$ORG/audit-log?phrase=action:workflows.created_workflow_run&per_page=100" --jq '.[] | [."@timestamp", .actor, .repo, .event, .head_branch] | @tsv'
# Unsigned commits on the default branch that did not come from a merged PR
gh api "/repos/$ORG/<repo>/commits?per_page=100" --jq '.[] | select(.commit.verification.verified==false) | [.sha, .commit.author.date, .author.login] | @tsv'
# Workflow files that serialise all secrets
grep -RIn 'toJSON(secrets)' .github/workflows/
```

3. Flag: `workflow_dispatch` runs of release / pre-release / signing workflows on branches other than the default or release branches; branches named like `probe/*`, `security/lab-secrets-*`, `test-run`; any workflow step reaching `webhook.site`; releases with no associated merged PR within the preceding hour.
4. Compare npm publish times with releases and with PR merges - a publish minutes after an unsigned direct commit is the bee-js pattern.

## Act

- **Expected benign:** maintainers dispatching release workflows manually from the default branch; bots that push signed, reviewed commits; security testing branches announced in advance.
- **Action on match (a):** move funds from the Swarm node wallet to a key generated on a clean host, rotate the `swarm.key` / password from `config.yaml`, uninstall 0.56.2 and pin 0.56.1 or a later clean release, then run H2 / k2 for stage 3.
- **Action on match (b):** suspend the identity, revoke its tokens and SSH keys, review every release and package version it produced, unpublish or deprecate them, and rotate all secrets the workflows could read. Harden: required signed commits and PR reviews on release branches, environment protection rules (required reviewers, deployment branch policy) around signing and trusted-publishing environments, `workflow_dispatch` restricted to protected branches, and egress control on runners.
- **Escalation:** any confirmed unauthorised release -> customer notification and advisory (as GHSA-hh7j-5m3j-23pf did for bee-js).
- **Exit criteria:** no 0.56.2 installs remain; wallets rotated; no release in scope lacks a reviewed PR; signing environments require approval.
