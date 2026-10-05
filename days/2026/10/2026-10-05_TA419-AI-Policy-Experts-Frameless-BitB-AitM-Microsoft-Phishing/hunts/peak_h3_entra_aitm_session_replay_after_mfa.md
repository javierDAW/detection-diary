# PEAK hunt H3 - Entra session replay after a relayed MFA sign-in

## Prepare

**Hypothesis.** If a user completed the fake OneDrive sign-in, then Entra shows a successful interactive sign-in from the user's own network that satisfied MFA through the first-party OfficeHome client
(`4765445b-32c6-49b0-83e6-1d93765276ca`), followed by activity on the same session ID from a different IP and network. Proofpoint reports that the kit relays the real Microsoft sign-in (password, MFA and
conditional-access checks), captures the session cookie, accepts "Keep me signed in" and submits one-time codes automatically, so the victim sees a normal sign-in. Proofpoint does not describe what the actor did with the sessions.

**Why third.** It is the one check that works whatever the domain or lure was, and it is the check that decides whether a click became an account compromise.

**Scope.** Users who received mail from H1, clicked in H2, or are in the high-value group. Look back 30 days from the click.

**Data quality check first.** Confirm that `SigninLogs` and `AADNonInteractiveUserSignInLogs` are both exported to the workspace and that `SessionId` is populated. Without the non-interactive table the replay is invisible.

## Execute

```kql
// Sentinel: full query in kql/k3. This version lists all sessions that used more than one IP address within two hours for the OfficeHome client.
SigninLogs
| where TimeGenerated > ago(30d) and AppId == "4765445b-32c6-49b0-83e6-1d93765276ca" and ResultType == 0
| join kind=inner (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(30d) and ResultType == 0) on SessionId, UserPrincipalName
| where IPAddress != IPAddress1
| project TimeGenerated, UserPrincipalName, SessionId, FirstIP = IPAddress, ReplayIP = IPAddress1, ReplayApp = AppDisplayName1, ReplayResource = ResourceDisplayName1
```

```powershell
# Author: Jarmi
# After a suspected exposure: end the sessions, inspect registered methods and mailbox rules.
Connect-MgGraph -Scopes "User.ReadWrite.All","UserAuthenticationMethod.Read.All"
Revoke-MgUserSignInSession -UserId user@contoso.com
Get-MgUserAuthenticationMethod -UserId user@contoso.com | Select-Object Id, AdditionalProperties
Get-InboxRule -Mailbox user@contoso.com | Select-Object Name, Enabled, ForwardTo, RedirectTo, DeleteMessage
```

## Act

**The same session on a second IP and ASN** soon after an MFA sign-in is a strong replay signal. Revoke the sessions, reset the password, review the registered authentication methods and mailbox rules, and search the audit
log for mail access and file downloads from the second IP. Resetting the password alone does not end a stolen session cookie.

**A second IP that belongs to a known VPN or proxy egress** is a likely false positive; add the range to the exclusion list in the query and keep watching the account.

**No replay** does not show that the page was not completed. If H2 shows that the user loaded the relay page, revoke the sessions anyway and make the user sign in again from a managed device.
