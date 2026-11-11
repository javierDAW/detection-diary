# PEAK hunt H3 - Find our own exposed application secrets before an agent does: GitHub exposure, repo scanning and long-lived Entra secrets

## Prepare

- **Hypothesis:** at least one Entra ID client secret, storage connection string, publishing profile or AI-provider API key belonging to us is (or was) committed to a public or reachable GitHub repository, and long-lived secrets make any leak exploitable for months.
- **Why:** Microsoft Threat Intelligence (2026-11-05) reports that from August 2026 an agentic AI framework sent large volumes of GitHub secret-search queries combining a target organisation name with secret keywords, cloud-service keywords or AI-provider keywords, looking for OAuth / application credentials and AI inference API keys, and then used them against Entra ID and Azure (H1, H2). It also searched Azure DevOps for further secrets after access.
- **Honesty:** this hunt is preventive and organisation-specific; it does not use campaign indicators. The YARA rules are credential-hygiene scanners, not campaign signatures. The documented Entra secret format (`xxx8Q~` + 34 characters) covers current secrets only; older formats are not matched by the regex.
- **Scope:** all GitHub organisations and personal repos of employees that reference the company name, Azure DevOps repos, container registries and build artefacts; every app registration in every tenant.
- **Confidence:** high for any secret found that still authenticates; medium for format-only matches.

## Execute

**Data sources / content:** `yara/exposed_entra_app_secrets_hygiene.yar` (rules `Hygiene_Entra_Client_Secret_In_Text_File`, `Hygiene_AI_Provider_Or_Azure_Publishing_Credential_Names`), GitHub secret scanning / push protection alerts, Microsoft Graph.

1. Pull GitHub secret scanning alerts for your organisations (read-only):

```bash
# Author: Jarmi
gh api --paginate "/orgs/<your_org>/secret-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | [.number, .secret_type, .repository.full_name, .created_at, .validity] | @tsv'
```

2. Search public GitHub the way the actor did - your organisation name together with words such as `client_secret`, `AZURE_CLIENT_SECRET`, `AccountKey`, `OPENAI_API_KEY` - using GitHub code search in the web UI, and record every hit outside your control.
3. Scan local clones, history included, with the YARA hygiene rules:

```bash
# Author: Jarmi
RULES=./yara/exposed_entra_app_secrets_hygiene.yar
for r in /srv/repos/*/; do
  yara -r -s "$RULES" "$r"                                   # working tree
  git -C "$r" log -p --all > "/tmp/$(basename "$r")_history.patch"   # full history, deleted secrets included
  yara -s "$RULES" "/tmp/$(basename "$r")_history.patch"
done
```

4. Inventory long-lived client secrets across the tenant (read-only, Microsoft Graph PowerShell):

```powershell
# Author: Jarmi
Connect-MgGraph -Scopes "Application.Read.All"
$now = Get-Date
Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials |
  ForEach-Object {
    $app = $_
    foreach ($p in $app.PasswordCredentials) {
      [pscustomobject]@{
        App          = $app.DisplayName
        AppId        = $app.AppId
        KeyId        = $p.KeyId
        Hint         = $p.Hint
        Start        = $p.StartDateTime
        End          = $p.EndDateTime
        LifetimeDays = [int]($p.EndDateTime - $p.StartDateTime).TotalDays
        Expired      = $p.EndDateTime -lt $now
      }
    }
  } | Where-Object { $_.LifetimeDays -gt 180 -or $_.Expired } | Sort-Object LifetimeDays -Descending | Format-Table -AutoSize
```

   Equivalent with az CLI:

```bash
# Author: Jarmi
az ad app list --all --query "[?length(passwordCredentials) > \`0\`].{app:displayName, appId:appId, secrets:passwordCredentials[].{hint:hint, start:startDateTime, end:endDateTime}}" -o json
```

5. Correlate every leaked secret `hint` with H1 sign-in failures / successes for that AppId.

## Act

- **Expected benign:** test fixtures with fake values that happen to match the format; expired secrets already removed from the app (still clean the repo).
- **Action on match:** rotate first, clean second - remove the credential from the app registration, issue a new one (prefer certificates or workload identity federation for GitHub Actions / Azure DevOps over client secrets), then purge the secret from history (`git filter-repo`) and invalidate caches and forks you control. Enable GitHub secret scanning push protection and an app-management policy that caps secret lifetime and blocks new password credentials where possible. Rotate AI-provider keys at the provider.
- **Escalation:** any exposed secret that still authenticates, or any 7000215 / 7000222 from an external IP for that AppId, goes to H1 / H2 as an incident.
- **Detections:** run the YARA rules in CI on every push; alert on new password credentials added to apps (`AuditLogs` "Update application - Certificates and secrets management").
- **Exit criteria:** no open secret scanning alerts; no client secret with lifetime above your policy (for example 180 days); every app used by CI/CD on federated credentials.
- **Caveat:** deleting a commit does not remove a secret that was already public - assume it was harvested within minutes and rotate.
