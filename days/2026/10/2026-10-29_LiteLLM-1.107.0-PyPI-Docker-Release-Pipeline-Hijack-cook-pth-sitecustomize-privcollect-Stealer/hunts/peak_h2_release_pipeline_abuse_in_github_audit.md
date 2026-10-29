# PEAK hunt H2 - release pipeline abuse: throwaway branches, secret exfiltration and approval laundering

## Prepare

**Hypothesis.** If an attacker holds maintainer OAuth tokens (the LiteLLM case), the GitHub audit log and Actions history show: short-lived `ci-tmp-*` branches whose workflows post secrets to an external endpoint, workflow runs deleted minutes later, a release workflow that suddenly accepts a source organization other than your own, branch-protection overrides by an organization owner, and two different maintainer tokens triggering and approving the same production release.

**Why second.** The compromised wheel was only the last step. The same hygiene gap (unscoped GitHub CLI OAuth tokens, a relaxed two-person gate, fork-sourced builds) exists in any project that publishes to PyPI, npm or a registry from CI.

**Scope.** GitHub organization audit log (git, workflows, repo, protected_branch events), Actions run history and runner egress logs for 60 days. Enterprise audit log streaming is needed for older data.

## Execute

```bash
# Author: Jarmi
# Organization audit log: protection overrides, run deletions and workflow edits (gh CLI, org owner).
gh api -X GET "/orgs/<ORG>/audit-log" -f phrase='action:protected_branch.policy_override created:>=2026-10-01' --paginate
gh api -X GET "/orgs/<ORG>/audit-log" -f phrase='action:workflows.delete_workflow_run created:>=2026-10-01' --paginate
gh api -X GET "/repos/<ORG>/<REPO>/branches" --paginate -q '.[].name' | grep -E '^ci-tmp-[0-9a-f]{6}$'
# Release workflow definition: any input that lets the source owner or ref be chosen at dispatch time.
grep -rnE 'source_owner|inputs\.(owner|repo|source)' .github/workflows/ | head
```

```kql
// Author: Jarmi
// Runner egress to the exfiltration channel used on 2026-10-10 and 2026-10-12 (Defender XDR, runners onboarded as devices).
DeviceNetworkEvents
| where Timestamp > ago(60d) and RemoteUrl has "webhook.site"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Act on

- A `ci-tmp-*` branch or a deleted run near a secret-bearing workflow: rotate every secret that workflow could read and review who created the branch from which token.
- A protection override by an owner token outside an incident: revoke the token, move owners to scoped credentials with sensitive-action re-authentication.
- Same release triggered and approved from the same source IP: the two-person gate is not independent, restore a different-identity, different-device rule.

## Knowledge

Deleting a run does not delete the commit: the postmortem notes the exfiltration and revert commits stay retrievable by SHA, and the organization audit log recorded each override. Build from tagged commits in your own organization only.
