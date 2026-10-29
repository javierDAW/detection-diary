# PEAK hunt H3 - use of stolen cloud and LLM credentials after exfiltration

## Prepare

**Hypothesis.** Credentials taken by the stealer (AWS keys and instance-role sessions, GCP service accounts, Azure CLI tokens, LLM provider keys, SSH and GitHub tokens) are validated within hours: Wiz reports AWS calls beginning about 4.5 hours after exfiltration, 16:20 to 17:01 UTC on 2026-10-21, from 168.100.8.57 and 165.227.201.8, running `sts:GetCallerIdentity`, then `bedrock:ListFoundationModels` and a model listing, a pattern consistent with LLMjacking, plus IAM enumeration in some accounts.

**Why third.** Even a clean host is not proof of safety if a build image or notebook ran the release. The cloud audit trail shows whether the secrets were actually used and which identities to rotate first.

**Scope.** CloudTrail (management and Bedrock events) for 2026-10-21 to today, GCP Audit Logs, Azure sign-in and activity logs, LLM provider key-usage dashboards, IMDS access logs from CI runners and nodes.

## Execute

```sql
-- Author: Jarmi
-- Athena over CloudTrail: validation calls from the two reported addresses or from any non-corporate source after 2026-10-21 11:39 UTC.
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventtime >= '2026-10-21T11:39:00Z'
  AND (sourceipaddress IN ('168.100.8.57','165.227.201.8')
       OR eventname IN ('GetCallerIdentity','ListFoundationModels','ListRoles','ListUsers','ListAccessKeys','ListAccounts','DescribeTrails'))
ORDER BY eventtime;
```

```bash
# Author: Jarmi
# Which cloud and provider secrets lived on a suspect host (inventory before rotation, run from a clean machine on a disk image or mounted volume).
ls -la ~/.aws ~/.config/gcloud ~/.azure ~/.ssh ~/.config/gh 2>/dev/null
env | grep -iE 'AWS_|OPENAI|ANTHROPIC|COHERE|AZURE|GOOGLE_APPLICATION|DATABASE_URL|LITELLM'
```

## Act on

- Any call from the two IPs, or a GetCallerIdentity followed by a Bedrock model listing from an unexpected source: rotate that identity and every key stored in its reachable config now, then review billing for model-invocation spikes.
- LiteLLM proxy database reachable from the host: assume every row of `LiteLLM_CredentialsTable` (up to 500 read) is exposed and rotate each upstream provider key.
- No hits but the host ran 1.107.0: rotate anyway; the stealer also takes SSH keys, GPG keys, browser cookies and shell history.

## Knowledge

Credential validation is the attacker's confirmation step and the defender's best tripwire: unexpected `GetCallerIdentity` from an unfamiliar address is a cheap, high-signal alert for any leaked key.
