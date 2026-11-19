# PEAK hunt H2 - which CI runners exposed pipeline credentials to the collector?

## Prepare

**Hypothesis.** If a GitHub Actions job or Azure DevOps pipeline installed agent-framework 1.26.1 or 1.26.2 on or after 2026-11-17 20:35 UTC, the collector read environment variables (TOKEN / SECRET / KEY / AZURE / AWS / GITHUB / OPENAI / HF_ patterns) from its own process and up to 300 other processes via `/proc/*/environ`, `SYSTEM_ACCESSTOKEN` on Azure DevOps, Azure managed-identity tokens on Azure-hosted agents, and, with 1.26.2, a GitHub Actions OIDC token when the job had `id-token: write`, plus runner directories.

**ATT&CK.** T1552.001 (Credentials In Files), T1552.005 (Cloud Instance Metadata API), T1528 (Steal Application Access Token), T1567 (Exfiltration Over Web Service).

**Data sources.** GitHub Actions run logs and the organisation audit log, Azure DevOps pipeline run history and auditing, runner host telemetry (`DeviceNetworkEvents`, Sysmon EID 3 / 22, proxy logs), workflow files (`permissions:` blocks), pipeline variable groups and service connections.

**Scope window.** 2026-11-17 20:35 UTC onward; focus on runs between 20:35 and about 21:30 UTC plus any later run that used a cached wheel or an image built in the window.

## Execute

1. List every pipeline run in the window whose install step resolved `agent-framework` (search run logs for `agent_framework-1.26.1` or `agent_framework-1.26.2`).

```bash
# Author: Jarmi
# GitHub: runs in the window per repository, then grep the logs for the malicious wheel names.
gh run list -R ORG/REPO --created '2026-11-17T20:30:00Z..2026-11-18T23:59:59Z' --json databaseId,workflowName,headBranch,createdAt
gh run view RUN_ID -R ORG/REPO --log | grep -nE 'agent[-_]framework[-=]=?1\.26\.[12]'
# Workflows that grant OIDC: these runs could also leak an OIDC token (1.26.2).
grep -rn 'id-token: *write' .github/workflows/
```

2. On self-hosted runners, check egress to webhook.site and IMDS from python in the window (`kql/k2`, `sigma/03`, `sigma/05`, Suricata 9149001-9149004).
3. For each matching run, inventory the secrets in scope: repository and organisation secrets referenced by the job, `GITHUB_TOKEN` permissions, Azure service connections, variable groups, cloud federated credentials trusting the repository OIDC subject.

## Expected results

- Clean: no run resolved the malicious versions.
- Exposed: a list of runs, the secrets each run could see, and whether `id-token: write` or an Azure managed identity was available.

## False positives

- Runs that downloaded the wheel but failed before any Python interpreter started (rare; the install itself starts Python, so treat as exposed).
- webhook.site traffic from integration tests unrelated to the window.

## Action on match

- Rotate every secret the run could read, revoke and reissue Azure DevOps PATs and service connection secrets, and narrow OIDC federated credential subjects.
- `GITHUB_TOKEN` expires at job end, but check the audit log for its use during the job lifetime.
- Pin dependencies with hashes (`pip install --require-hashes`) and drop `id-token: write` from jobs that do not deploy.

## Knowledge

A runner is a credential concentrator: one poisoned dependency at install time sees every secret the job maps into its environment, and `/proc/*/environ` reading extends that to sibling processes on the same host.
