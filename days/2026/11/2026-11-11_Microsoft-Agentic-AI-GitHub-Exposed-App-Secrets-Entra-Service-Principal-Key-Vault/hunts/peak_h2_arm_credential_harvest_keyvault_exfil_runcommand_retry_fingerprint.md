# PEAK hunt H2 - Service principal harvesting credentials through ARM, exfiltrating Key Vault secrets and using VM Run Command, with an automation retry fingerprint

## Prepare

- **Hypothesis:** a service principal signed in with a leaked secret is being driven by an automated agent that enumerates subscriptions, resource groups, permissions and AI model deployments, then calls credential-returning ARM operations (storage account keys, App Service settings and publishing credentials, connection strings, AI/ML connections and datastores, AKS user credentials), reads Key Vault secrets, touches storage, and runs commands on VMs via Run Command.
- **Why:** Microsoft Threat Intelligence (2026-11-05) describes exactly this chain, including one case where GitHub secret search to Key Vault exfiltration took five minutes, use of a compromised OAuth app with Azure VM Run Command, validation of stolen Azure AI resources, and Graph access to SharePoint / OneDrive files and mailbox items (mostly searches). It also reports an adaptive-troubleshooting fingerprint: ARM calls from `199.19.77.84` returned HTTP 400 because of a wrong api-version and the same call was resent 28-80 seconds later with a corrected api-version (for example `2023-07-01`) and returned 200 - examples include Key Vault secret metadata enumeration, a SQL server firewall rules GET and an Application Insights query POST.
- **Honesty:** request shapes, user agents and volumes are not published; the operation list in the rules is generic Azure knowledge. `AzureActivity` does not record the api-version or plain GET reads, so the retry fingerprint can only be approximated there (Failed then Succeeded within 120 s on the same caller / operation / resource).
- **Scope:** 14 days of `AzureActivity`, Key Vault `AuditEvent` (`AzureDiagnostics` or `AZKVAuditLogs`), `StorageBlobLogs`, `AADServicePrincipalSignInLogs`; Defender XDR `CloudAuditEvents` / `CloudStorageAggregatedEvents` / `GraphAPIAuditEvents` where available (verify columns in your tenant).
- **Confidence:** medium for credential-returning operations or Run Command by a non-baselined service principal; high when combined with an H1 hit; low-medium for the retry fingerprint on its own.

## Execute

**Data sources / content:** `sigma/02_agentic_ai_arm_credential_listing_or_runcommand_from_published_ips.yml`, `kql/k2_azure_activity_credential_returning_arm_ops_runcommand_retry_and_multi_resource_tokens.kql`, `kql/k3_keyvault_secret_enumeration_by_spn_and_storage_access_from_campaign_ips.kql`, `suricata/agentic_ai_secret_abuse_campaign_ips.rules` (marginal - cloud-API traffic is not visible to a network sensor).

1. Baseline automation AppIds that legitimately call `listKeys` / `publishxml` / `config/list` (backup, IaC, DevOps) into `<add_known_automation_appids>`.
2. Run k2 and k3. Prioritise service principals that appear in more than one signal (credential listing + Key Vault burst + tokens for ARM, Key Vault, Storage and Graph within 1 h).
3. For each candidate, build a timeline from first sign-in to last data-plane access:

```bash
# Author: Jarmi
SPN_APPID="<appId>"; START="2026-10-28T00:00:00Z"
for SUB in $(az account list --query "[].id" -o tsv); do
  az monitor activity-log list --subscription "$SUB" --start-time "$START" --max-events 5000 \
    --query "[?claims.appid=='$SPN_APPID'].{time:eventTimestamp, op:operationName.value, status:status.value, ip:httpRequest.clientIpAddress, res:resourceId}" -o table
done
```

4. Look at the retry fingerprint: the same operation on the same resource failing then succeeding seconds later, repeatedly across resource types, is consistent with an agent correcting its own requests. If you have raw ARM request telemetry with HTTP status and api-version, confirm the 400 -> 200 pair with a changed api-version.
5. For any Run Command, read the script content and output (`Microsoft.Compute/virtualMachines/runCommand/action` in Activity Log; on the VM, `C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\` or `/var/lib/waagent/run-command/download/` on Linux) and treat the VM as a separate host investigation.

## Act

- **Expected benign:** backup and DR tooling listing storage keys, deployment pipelines fetching publishing profiles, Kubernetes tooling calling `listClusterUserCredential`, apps reading their own Key Vault secrets at start-up from a stable IP.
- **Action on match:** every secret returned to the attacker is compromised. Rotate storage account keys (both), regenerate App Service publishing credentials, rotate connection strings and database passwords, rotate every Key Vault secret the principal read (`SecretGet` items in k3), reset AKS credentials (`az aks rotate-certs` or rotate the local accounts / disable local accounts), regenerate AI resource keys, and disable or delete the compromised service principal credentials (H1). Review Graph mailbox / file access for data exposure notification.
- **Escalation:** VM Run Command or AKS credential use means code execution on compute - open host-level IR. Graph mailbox or SharePoint access may trigger privacy obligations.
- **Detections:** promote the k2 "credential-returning ARM ops by non-baselined SPN" block and the k3 Key Vault burst block to scheduled rules; keep Sigma 02 for the published IPs.
- **Exit criteria:** every credential returned by ARM or read from Key Vault in the window has been rotated; no activity from the principal or the source IPs after rotation.
- **Caveat:** an agent that adapts its own api-version will equally adapt IPs and user agents; durable signals are behavioural (secret-returning operations, multi-resource token acquisition, fast fail-then-succeed retries).
