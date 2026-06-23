# PEAK Hunt H1 — SaaS Permission Creep: Identify Stale Privileged Cloud Accounts

## Hunt metadata

| Field | Value |
|---|---|
| Hunt ID | H1 |
| Hypothesis | Users holding privileged SaaS roles (Global Admin, Exchange Admin, Security Admin) who have not performed any role-relevant action in >= 30 days represent permission creep — the structural precondition for insider and manipulated-insider abuse identified by Intel 471 |
| PEAK phase | Prepare |
| MITRE | T1078.004 Cloud Accounts, T1087.004 Cloud Account Discovery |
| Primary data source | Entra ID AuditLogs (Sentinel), Microsoft Graph API privileged role report |
| Reference | Intel 471 Cloud Insider Threat Report 2026 via Help Net Security 2026-06-11 |
| Author | Jarmi |
| Date | 2026-06-23 |

## Hypothesis rationale

Intel 471's June 2026 report identifies permissions creep as the primary structural enabler of insider attacks on cloud platforms. Access accumulates over tenure without review, third-party app connections grant persistent reach, and offboarding processes fail to revoke SaaS tokens promptly. The samsepi0l April 4 2026 auction specifically offered "master admin + Slack + Okta access" — privileged roles that likely accumulated through exactly this pattern. This hunt identifies the footprint before an insider or external actor exploits it.

## Data collection

```powershell
# Pull all Entra ID privileged role assignments via Graph API
Connect-MgGraph -Scopes "RoleManagement.Read.Directory","AuditLog.Read.All"

$privileged_roles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "Security Administrator",
    "SharePoint Administrator",
    "User Administrator"
)

foreach ($role in $privileged_roles) {
    $roleId = (Get-MgDirectoryRole -Filter "displayName eq '$role'").Id
    if ($roleId) {
        Get-MgDirectoryRoleMember -DirectoryRoleId $roleId |
            Select-Object @{N="Role";E={$role}},
                          @{N="DisplayName";E={$_.AdditionalProperties.displayName}},
                          @{N="UPN";E={$_.AdditionalProperties.userPrincipalName}},
                          @{N="Id";E={$_.Id}}
    }
}
```

```kql
// Sentinel: last activity per privileged user
AuditLogs
| where TimeGenerated >= ago(90d)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(Actor)
| summarize LastActivity=max(TimeGenerated) by Actor
| join kind=inner (
    AuditLogs
    | where Category == "RoleManagement"
    | where OperationName has "Add member to role"
    | extend TargetUser=tostring(TargetResources[0].userPrincipalName),
             RoleName=tostring(TargetResources[0].displayName)
    | project TargetUser, RoleName, RoleAssignTime=TimeGenerated
) on $left.Actor == $right.TargetUser
| where LastActivity < ago(30d)
| project Actor, RoleName, RoleAssignTime, LastActivity,
          DaysSinceActivity=datetime_diff('day',now(),LastActivity)
| sort by DaysSinceActivity desc
```

## Analysis

For each user returned:
1. Confirm current employment status with HR (terminated = immediate revocation required).
2. Review last sign-in time in Entra ID Sign-in logs.
3. Check for active service principal or app registrations tied to the account.
4. Enumerate third-party OAuth app grants (`Get-MgUserOauth2PermissionGrant`).
5. Verify offboarding checklist completion — did access removal actually happen?

## Expected output

A prioritised list of accounts with stale privileged roles. Accounts with last activity > 90 days and confirmed offboarding should be treated as active incidents (access already compromised or available for insider abuse).

## Escalation criteria

- Any privileged account with last activity > 30 days = remediation ticket.
- Any privileged account for a terminated employee = incident response.
- Any account where `Get-MgUserOauth2PermissionGrant` shows third-party app with broad scopes (Mail.Read, Files.ReadWrite.All) = escalate to application security.
