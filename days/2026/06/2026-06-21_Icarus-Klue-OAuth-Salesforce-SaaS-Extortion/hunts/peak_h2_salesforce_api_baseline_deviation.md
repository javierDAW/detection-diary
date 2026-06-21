# PEAK Hunt H2 — OAuth Refresh Token Exercise from Non-Vendor IP

**Hunt ID:** H2  
**Case:** 2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion  
**Author:** Jarmi  
**Date:** 2026-06-21  
**Technique:** T1528, T1550.001  

## Hypothesis

An OAuth refresh token for a Salesforce-connected integration app has been exercised from
an IP address outside our approved integration vendor IP ranges in the past 30 days.

**Baseline:** Salesforce integration refresh token exchanges should originate exclusively
from the documented IP ranges of the integration vendor (e.g., Klue, HubSpot, Gong, Chorus).
Any refresh token exchange from a VPS/data-center IP not in those ranges represents
a stolen token being replayed by an attacker.

**Why this matters:** This hunt catches token theft regardless of which specific vendor
is compromised. It is the durable, vendor-agnostic detection for the OAuth-abuse attack class
that Icarus, UNC6395 (Drift), and ShinyHunters have all used. The specific vendor rotates;
the behavioral fingerprint (token refresh from non-vendor IP) does not.

## Data Sources

- Salesforce Event Monitoring: EventLogFile type OauthToken
- Azure AD / Entra ID Audit Logs: Service Principal Sign-in logs
- Identity Provider audit logs

## Hunt Query (Salesforce SOQL — Event Monitoring)

```soql
SELECT Username, SourceIp, ConnectedAppName, ConnectedAppId,
       TokenType, CreatedDate
FROM EventLogFile
WHERE EventType = 'OauthToken'
  AND CreatedDate = LAST_N_DAYS:30
  AND GrantType = 'refresh_token'
ORDER BY CreatedDate DESC
LIMIT 500
```

Post-query filter: Enrich SourceIp with ASN lookup; flag any row where ASN is NOT
in the allowlist of approved vendor ASNs (compile from vendor documentation).

## Hunt Query (KQL — Azure AD Sign-in Logs for Service Principals)

```kql
// Service principal OAuth token grants from unexpected ASN
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ResourceDisplayName has "Salesforce"
| extend ASN = tostring(NetworkLocationDetails[0].networkNames)
| where ASN !in (<add_known_vendor_asn_list>)
| project TimeGenerated, ServicePrincipalName, IPAddress, ASN,
          ResourceDisplayName, ResultType, ConditionalAccessStatus
| sort by TimeGenerated desc
```

## Analysis Steps

1. Pull all OAuth refresh_token grants for Salesforce-connected apps in the past 30 days.
2. Compile approved IP ranges from vendor documentation for each connected integration:
   - Klue (if still authorized): document CIDR ranges from klue.com infrastructure
   - HubSpot: documented in HubSpot Trust Portal
   - Gong: documented in Gong help center
3. Flag any refresh token grant from an IP outside approved vendor ranges.
4. For each flagged result: check what Salesforce objects were queried by that token in the
   subsequent session (cross-join RestApiRequest EventLogFile on token issuance timestamp).
5. If any high-value objects (Account, Contact, Opportunity, Quote) were queried after a
   flagged refresh, treat as confirmed exfiltration and escalate immediately.
6. Revoke all refresh tokens for the affected connected app immediately upon any flag.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| Token refresh from VPS/data-center IP not in vendor allowlist | Confirmed theft; revoke token, escalate to IR, notify affected vendor |
| Token refresh from residential IP | Possible developer testing; verify with team before revoking |
| No flagged results | Extend look-back to 90 days; assess whether vendor allowlist is complete |
| Multiple IPs outside allowlist within same day | Indicates active exfiltration in progress; immediate revocation and containment |

## References

- Salesforce OAuth Event Monitoring: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/using_resources_event_log_files.htm
- ReliaQuest Threat Spotlight: https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft
- Huntress Klue investigation: https://www.huntress.com/blog/klue-breach-investigation
