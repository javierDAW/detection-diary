# PEAK H2 — ARM Control-Plane Credential Burst (publishxml + Key Vault + listkeys)

## Hypothesis

A threat actor with valid privileged Azure RBAC permissions on a production
subscription is executing a burst of Azure Resource Manager operations that,
together, harvest application credentials, Key Vault secrets, and Storage
account keys within a thirty-minute window. The operation set is normally
spread across distinct administrative tasks owned by different teams; their
co-occurrence under a single caller identity is a high-confidence indicator
of intent to exfiltrate.

## Why this discriminates

Each operation in isolation has legitimate use:

- `microsoft.web/sites/publishxml/action` — developer deploy.
- `microsoft.keyvault/vaults/accesspolicies/write` — administrator change.
- `microsoft.keyvault/vaults/secrets/read` — application or admin.
- `microsoft.storage/storageaccounts/listkeys/action` — administrator
  rotation or initial setup.
- `microsoft.sql/servers/firewallrules/write` — administrator scope grant.

Their concentration under one caller within thirty minutes is the pattern
Microsoft Defender Security Research published for Storm-2949 and reflects
the credential-harvesting phase of the cloud-wide breach.

## Data sources

- Microsoft Defender XDR `CloudAuditEvents` table (Azure Resource Manager
  data source).
- Microsoft Sentinel `AzureActivity` table.
- Azure Activity Log streamed to Event Hub for offline replay.

## Query (KQL)

See `../kql/storm2949_arm_publishxml_keyvault_storage_chain.kql`.

## Expected benign vs malicious

- **Benign:** an Infrastructure-as-Code pipeline service principal
  (Terraform, Bicep, ARM template) batches publishxml plus listkeys during
  initial provisioning. Caller is a service principal with displayName
  matching the pipeline naming convention.
- **Malicious:** caller is a user principal (UPN form), source IP is
  outside the corporate range, the burst includes Key Vault secret reads
  AND Storage `listkeys` AND App Service `publishxml` together. Caller has
  recently been targeted by an SSPR + Authenticator rebind chain (cross
  reference H1).

## Action on match

1. Freeze the caller principal: disable, revoke tokens, alert IR.
2. Inventory every resource touched (resource IDs from the query output).
3. Rotate every Key Vault secret read during the window (timestamped
   per-secret read events in Key Vault diagnostic logs).
4. Regenerate **both** Storage account keys for every storage account where
   `listkeys` fired — rotating only one key leaves SAS tokens signed with
   the other key still valid.
5. Rotate App Service publishing profile credentials and pause any active
   deployments from those credentials.
6. Recover SQL firewall original ruleset and confirm whether any rule was
   created and deleted during the window.

## References

- Microsoft Security Blog — Storm-2949 (2026-05-18).
- Microsoft Learn — Azure Key Vault diagnostic logging guidance.
