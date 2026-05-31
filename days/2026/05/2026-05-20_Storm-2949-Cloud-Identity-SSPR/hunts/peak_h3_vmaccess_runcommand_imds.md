# PEAK H3 — VMAccess Local Admin Plus Run Command IMDS Token Request

## Hypothesis

A threat actor with Azure RBAC permissions over a virtual machine is using
the VMAccess extension to plant a new local administrator account and then
issuing an Instance Metadata Service (IMDS) token request via Run Command,
attempting to bridge from cloud control-plane access to host execution and
to managed-identity token theft against downstream Azure resources such as
Key Vault.

## Why this discriminates

The signature primitive is a PowerShell or pwsh process **parented by
`WindowsAzureGuestAgent.exe`** (the Azure VM agent that materialises Run
Command invocations) calling `169.254.169.254/metadata/identity/oauth2/token`
with the `Metadata: true` header. Genuine automation rarely requests IMDS
tokens via interactive Run Command — that traffic normally lives inside
applications or DevOps tasks that have the token already.

When this is paired with a VMAccess extension write that creates a new
local administrator on the same VM within the preceding hour, the
combination becomes the canonical Storm-2949 cloud-to-host pivot.

## Data sources

- Microsoft Defender XDR `DeviceProcessEvents`,
  `DeviceNetworkEvents`.
- Microsoft Defender XDR `CloudAuditEvents` for
  `microsoft.compute/virtualmachines/extensions/write` (VMAccess) and
  `microsoft.compute/virtualmachines/runcommand/action`.
- Sysmon EID 1 with parent-tracking enabled and EID 22 (DNS to 169.254.169.254
  is not normally logged but the HTTP request will surface via EDR).

## Query (KQL)

See `../kql/storm2949_arm_publishxml_keyvault_storage_chain.kql` for the
ARM half. The host half:

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "WindowsAzureGuestAgent.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("169.254.169.254","Metadata:true","/metadata/identity")
| project Timestamp, DeviceName, AccountUpn, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## Expected benign vs malicious

- **Benign:** documented automation runbooks that call IMDS via Run
  Command for first-boot provisioning. Should be inventoried, named,
  excluded by exact command-line.
- **Malicious:** new VMAccess extension event creating a local
  administrator within 60 minutes of the Run Command; caller is a user
  principal (not a managed identity or pipeline service principal); the
  account name in VMAccess does not match the organization's naming
  convention.

## Action on match

1. Isolate the VM at network level immediately.
2. Capture memory and live triage before reboot (IMDS tokens are
   short-lived; if exfiltrated they are still usable for an hour).
3. Inventory local administrator group membership; remove any VMAccess-
   created admin not in inventory.
4. Audit Key Vault diagnostic logs for the managed-identity client ID of
   the VM — every secret access by that client ID within the suspicious
   window must be assumed compromised.
5. Re-image the VM and rotate any managed-identity-accessible secrets.

## References

- Microsoft Security Blog — Storm-2949 (2026-05-18).
- Microsoft Learn — Azure VM Run Command overview, VMAccess extension docs.
