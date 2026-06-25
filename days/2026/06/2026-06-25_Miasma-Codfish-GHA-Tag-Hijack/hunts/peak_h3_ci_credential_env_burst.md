# PEAK Hunt H3 — Credential Environment Variable Read Burst in CI Runner Context

**Hunt ID:** H3  
**Hypothesis:** At least one CI runner process in the environment has read three or more
distinct credential-class environment variable names (GITHUB_TOKEN, NPM_TOKEN, AWS_*,
AZURE_*, GCP_*) within a 60-second window within a single process tree. Legitimate
release workflows read at most one or two credential variables for their specific
purpose; a burst of credential reads across multiple platforms is characteristic of a
credential harvester payload (Miasma, Shai-Hulud variants).

**PEAK phase:** Credential Access  
**Data sources:** Syslog on self-hosted runners (auditd), EDR env-read telemetry,
GitHub Actions step logs (manual review)  
**Skill level:** Advanced  

## Procedure

### Step 1 — Enable auditd credential read monitoring on self-hosted runners

```bash
# Add auditd rules to capture environment reads of credential vars
# on Linux self-hosted runners
cat >> /etc/audit/rules.d/ci-runner-creds.rules << 'EOF'
-a always,exit -F arch=b64 -S getenv -F key=ci_credential_read
# Note: auditd does not directly audit getenv() calls at this granularity;
# use process exec monitoring + grep on /proc/<pid>/environ instead
-a always,exit -F arch=b64 -S execve -F key=ci_exec
EOF
augenrules --load
```

### Step 2 — Query Syslog for credential env dumps

```bash
# On Linux self-hosted runner, grep recent syslog for credential variable access
# This fires when a process reads /proc/self/environ or when a shell echoes env vars
grep -E 'GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY|AZURE_CLIENT_SECRET|GCP_SA_KEY' \
    /var/log/syslog /var/log/auth.log 2>/dev/null \
    | awk '{print $1, $2, $3, $NF}' \
    | sort | uniq -c | sort -rn | head -20
```

### Step 3 — Cross-reference with GitHub Actions run timestamps

```bash
# Identify the GitHub Actions run ID from runner logs
cat /home/runner/work/_temp/_runner_file_commands/*.env 2>/dev/null | grep GITHUB_RUN_ID

# Then audit the specific run in GitHub Actions UI:
# Org > Actions > workflow name > specific run > download logs
# Look for step "Cleanup Action" in the log output
```

### Step 4 — Check for unexpected npm publishes

```bash
# If NPM_TOKEN was in scope, check for unexpected publish events
# Run as the affected org/user identity
npm access list packages <username>
npm view <package> time --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for v, t in sorted(data.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f'{t}  {v}')
"
```

### Step 5 — Check for Miasma staging repo creation

```bash
# Search GitHub for repos created by victim accounts with Miasma markers
gh api "/users/<VICTIM_USERNAME>/repos" --jq '.[] | select(.description | contains("Miasma")) | {name, created_at, description}'
```

## Expected outcome

- **Clean:** Credential env reads are isolated to a single variable per workflow run
  and correlate with the workflow's declared secret usage.
- **Compromise indicator:** Three or more distinct credential classes read within
  60 seconds from the same process tree, or an unexpected npm publish, or a
  Miasma-branded repo created under a team member's account. Treat as active
  compromise: revoke all credentials in scope immediately, then investigate the
  npm publish log and GitHub audit log for downstream spread.

## Notes

- GitHub hosted runners rotate GITHUB_TOKEN per run; the token expires when the
  workflow finishes. NPM_TOKEN and cloud tokens are long-lived and must be rotated.
- The Miasma worm's propagation depends on NPM_TOKEN being present in the run;
  if only GITHUB_TOKEN is in scope, the impact is limited to the specific repo.
- Preventive control: set `permissions: contents: read` at the workflow level as the
  default; only grant additional permissions (write, packages) in the specific job
  that needs them. Use short-lived OIDC tokens for cloud access instead of static
  secrets where supported.
