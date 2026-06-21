# PEAK Hunt H3 — Stale NHI OAuth Grants Scoped to High-Value Salesforce Objects

**Hunt ID:** H3  
**Case:** 2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion  
**Author:** Jarmi  
**Date:** 2026-06-21  
**Technique:** T1528, T1078  

## Hypothesis

There are third-party apps currently authorized with OAuth access to our Salesforce environment
whose refresh tokens were issued more than 90 days ago and have not been rotated, and at least
some of these tokens are scoped to high-value CRM objects (Account, Contact, Opportunity, Quote).

**Baseline:** Every unrotated OAuth refresh token older than 90 days that is scoped to sensitive
Salesforce objects is a standing risk of the exact class that Icarus exploited. If a vendor's
backend is breached, any unrotated refresh token grants the attacker the same access as if they
had phished the integration account directly. The structural remediation is NHI lifecycle hygiene,
not a one-time revocation.

**Why this matters:** The Klue prototype credential that likely enabled the Icarus attack was
a long-lived, unrotated token from a deprecated integration project. This hunt surfaces the
full scope of similar standing risks across ALL Salesforce-connected integrations, not just Klue.

## Data Sources

- Salesforce Setup: Connected Apps OAuth Usage
- Salesforce SOQL: ConnectedApplication, OAuthToken event logs
- SIEM / CASB: Integration account activity baseline

## Hunt Query (Salesforce — Connected Apps OAuth Usage)

```
Salesforce Setup > Apps > Connected Apps OAuth Usage
Filter: Last Used Date > 90 days ago
Sort by: Last Used Date (ascending) to surface stale grants first
Columns to review: App Name, User, Last Used Date, App OAuth Scopes
```

## Hunt Query (Salesforce SOQL via Tooling API)

```soql
SELECT ConnectedApplication.Name, User.Name, User.Username,
       User.IsActive, LastModifiedDate
FROM OAuthToken
WHERE LastModifiedDate < LAST_N_DAYS:90
  AND ConnectedApplication.Name != null
ORDER BY LastModifiedDate ASC
LIMIT 200
```

## Hunt Query (Salesforce SOQL — Identify Scope)

```soql
SELECT Id, Name, Description, OauthScopes,
       CreatedDate, LastModifiedDate
FROM ConnectedApplication
WHERE OauthScopes INCLUDES ('full', 'api', 'refresh_token')
ORDER BY LastModifiedDate ASC
```

## Analysis Steps

1. Pull all connected apps with active OAuth tokens using the Tooling API query above.
2. Identify apps whose last token issuance or last use is more than 90 days ago.
3. For each stale app: determine the OAuth scope granted (Setup → Connected App → OAuth Policies).
4. Prioritize for revocation: apps with scope including 'api', 'full', 'data', or any scope
   that grants access to Account, Contact, Opportunity, or Quote objects.
5. Cross-reference app list against Klue's disabled integration list:
   Salesforce, HubSpot, SharePoint, Zoom, Gong, Chorus, Clari, Google Drive, Slack.
6. For any app not on an approved integration inventory, revoke immediately.
7. Establish token rotation schedule: 90-day maximum for NHI OAuth grants to Salesforce.
8. Document findings for NHI governance reporting.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| Unrotated tokens > 90 days, high-value scope | Revoke and reissue with least-privilege scope; document in NHI inventory |
| Prototype / POC app with valid token | Revoke immediately; prototype integrations should never have production tokens |
| Unrecognized app in connected app list | Treat as potential unauthorized grant; escalate to IR and revoke |
| All tokens < 90 days, well-scoped | No immediate action; implement 90-day rotation policy going forward |

## Automation Recommendation

Implement a scheduled Salesforce Flow or external automation that:
1. Queries OAuthToken table weekly for tokens older than 60 days.
2. Sends notification to the integration app owner requesting rotation.
3. Auto-revokes any token not rotated within 90 days (with override process for exceptions).

## References

- Salesforce Connected Apps OAuth Usage: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_connected_app_overview.htm
- OAuth Token Revocation: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_revoke_token.htm
- ReliaQuest Threat Spotlight: https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft
