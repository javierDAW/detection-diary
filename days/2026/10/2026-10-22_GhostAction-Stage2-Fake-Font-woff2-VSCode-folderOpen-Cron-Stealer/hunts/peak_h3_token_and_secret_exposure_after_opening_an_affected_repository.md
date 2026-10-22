# PEAK hunt H3 - Token and secret exposure after a developer opened an affected repository

## Prepare

**Hypothesis.** Stage 1 stole GitHub OAuth tokens with repo, workflow and read:org scopes and planted a workflow that sends secrets out; stage 2 re-infects through the repository. Owners who deleted stage 1 files without revoking access received stage 2 (OpenSourceMalware, via THN). So any account that shows a new OAuth grant, an unexpected workflow file or a secret gist must be treated as exposed together with every secret the workflows can reach.

**Why third.** It converts the endpoint finding into an account and secret scope, which decides what to rotate.

**Scope.** GitHub users and organisations, CI secrets, cloud keys, package registry tokens and AI provider keys reachable from the affected repositories.

**Data quality check first.** Confirm you can read the GitHub audit log (organisation or enterprise) and the security log of individual accounts for 2026-10-01 onward.

## Execute

```bash
# Author: Jarmi
# List OAuth and device-flow authorisations and workflow changes from the organisation audit log (requires audit log access).
gh api -X GET "/orgs/YOUR_ORG/audit-log?phrase=action:oauth_authorization+created:%3E2026-10-01&per_page=100" --jq '.[] | [.created_at,.actor,.action,.application_name] | @tsv'
gh api -X GET "/orgs/YOUR_ORG/audit-log?phrase=action:workflows.created_workflow_run+created:%3E2026-10-08&per_page=100" --jq '.[] | [.created_at,.actor,.repo,.name] | @tsv'
```

```bash
# Author: Jarmi
# List secret gists for a user and recently added workflow files in a repository (read-only).
gh gist list --secret --limit 50
git log --since=2026-10-01 --name-status -- .github/workflows .vscode/tasks.json public/fonts
```

## Act

1. Revoke the user's OAuth grants and personal access tokens from a clean device first, then clean the repository. Cleaning first leaves the token alive for stage 2.
2. Rotate every secret the planted workflows could read: AWS keys, PyPI and npm tokens, Git logins, Kubernetes credentials, SSH keys and AI provider keys.
3. Check CloudTrail, registry publish logs and cluster audit logs for use of those secrets after 2026-10-09.
4. Notify users who cloned the affected repositories (per the mitigation in the reporting).

## Knowledge

- Many victims in the earlier waves were hit again because their secrets were never rotated (GitGuardian).
- A secret gist is the stage 2 workflow's fallback when the POST fails; an unexpected secret gist is a strong lead.
