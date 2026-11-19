# PEAK hunt H3 - were exposed Azure, Azure DevOps, GitHub, PyPI or Hugging Face credentials used after the window?

## Prepare

**Hypothesis.** If the collector exfiltrated secrets from an affected host or runner, the operator validates or uses them after 2026-11-17 20:35 UTC: Entra ID sign-ins or token use for exposed service principals and managed identities from unfamiliar addresses, Azure DevOps API calls with stolen `SYSTEM_ACCESSTOKEN` or PATs, GitHub API or git activity with stolen tokens, PyPI uploads with stolen API tokens (a second-stage supply-chain push) and Hugging Face model or dataset pulls / pushes.

**ATT&CK.** T1078.004 (Cloud Accounts), T1550.001 (Application Access Token), T1528 (Steal Application Access Token), T1195.001 (follow-on package publication).

**Data sources.** Entra `SigninLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `AzureActivity`, Key Vault and Storage diagnostic logs, Azure DevOps audit stream, GitHub organisation audit log (including token-based `git.clone` events where enabled), PyPI project security history, Hugging Face access-token activity.

**Scope window.** 2026-11-17 20:35 UTC onward, for every identity found exposed in H1 / H2. No attacker infrastructure beyond the webhook.site URL was published, so this hunt relies on baselines, not on known IPs.

## Execute

1. Run `kql/k3` with `<add_known_ranges>` replaced by corporate, CI and Azure region egress ranges.
2. Azure resource plane for exposed managed identities (tokens can be replayed without a new sign-in row):

```kql
// Author: Jarmi
AzureActivity
| where TimeGenerated >= datetime(2026-11-17 20:30:00)
| where Caller in~ ("<add_exposed_identity_object_ids>")
| summarize Ops = make_set(OperationNameValue, 50), IPs = make_set(CallerIpAddress) by Caller
```

3. GitHub and PyPI:

```bash
# Author: Jarmi
# GitHub audit log for token activity in the window (organisation owner token required).
gh api -X GET "/orgs/ORG/audit-log" -f phrase='created:>=2026-11-17' -f include=all --paginate | jq -r '.[] | [.created_at,.action,.actor,.actor_ip,.programmatic_access_type] | @tsv'
# PyPI: review each project you publish for unexpected releases after the window.
for p in YOUR_PROJECTS; do curl -s "https://pypi.org/pypi/$p/json" | jq -r '.releases | to_entries[] | [.key, (.value[0].upload_time_iso_8601 // "")] | @tsv' | awk '$2 >= "2026-11-17T20:35"'; done
```

4. Hugging Face: review token activity and recent commits to owned models and datasets.

## Expected results

- No activity from unknown ranges for exposed identities; no unexpected releases or credential additions.
- Suspicious: first-seen IPs, credential additions to applications, new PyPI or Hugging Face uploads, Key Vault secret reads by an exposed identity outside its normal pattern.

## False positives

- New CI runner ranges or developer travel not yet in `<add_known_ranges>`.
- Legitimate releases cut by maintainers during incident response.

## Action on match

- Revoke sessions and credentials for the identity, rotate secrets it could read (Key Vault, storage keys), remove added application credentials, yank or delete unauthorised package releases and notify PyPI / Hugging Face.
- No match: still rotate every exposed credential; absence of logs is not proof of non-use.

## Knowledge

Managed-identity and OIDC tokens are short-lived but the access they grant during their lifetime can mint longer-lived footholds (new app secrets, PATs, package tokens); hunt for those footholds, not only for the original token.
