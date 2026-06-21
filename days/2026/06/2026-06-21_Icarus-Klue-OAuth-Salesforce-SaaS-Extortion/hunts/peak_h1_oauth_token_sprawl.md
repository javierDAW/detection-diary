# PEAK Hunt H1 — Integration Service Accounts with Salesforce Query Burst

**Hunt ID:** H1  
**Case:** 2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion  
**Author:** Jarmi  
**Date:** 2026-06-21  
**Technique:** T1530, T1567.002  

## Hypothesis

Integration service accounts in our Salesforce environment have issued more than 200 REST API
queries to the /query endpoint within any 30-minute window over the last 14 days.

**Baseline:** Legitimate SaaS integrations (Klue Battlecards, HubSpot, Gong, Chorus, Clari)
typically issue 10–50 queries per sync cycle. A burst exceeding 200 queries in 30 minutes,
especially following a sobjects enumeration, is a strong signal of bulk exfiltration.

**Why this matters:** In the Icarus/Klue campaign, the attacker sent ~1,000 queries in a
15-minute window after a slow reconnaissance phase. The transition from slow enumeration
to burst extraction is the most reliable behavioral fingerprint of this attack class.

## Data Sources

- Salesforce Event Monitoring: EventLogFile type RestApiRequest
- Microsoft Defender for Cloud Apps: CloudAppEvents
- SIEM: Proxy logs with URI patterns

## Hunt Query (Salesforce SOQL — Event Monitoring)

```soql
SELECT Username, SourceIp, Uri, COUNT(Id) queryCount,
       DATE_FORMAT(CreatedDate, 'yyyy-MM-dd HH:mm') timeWindow
FROM EventLogFile
WHERE EventType = 'RestApiRequest'
  AND CreatedDate = LAST_N_DAYS:14
  AND Uri LIKE '%/services/data/v%/query%'
GROUP BY Username, SourceIp, Uri, DATE_FORMAT(CreatedDate, 'yyyy-MM-dd HH:mm')
HAVING COUNT(Id) > 50
ORDER BY queryCount DESC
LIMIT 100
```

## Hunt Query (KQL — Defender XDR CloudAppEvents)

```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Salesforce"
| where Url has "/services/data/v" and Url has "/query"
| summarize QueryCount = count() by AccountDisplayName, IPAddress, bin(Timestamp, 30m)
| where QueryCount > 200
| sort by QueryCount desc
```

## Analysis Steps

1. Run query against Salesforce Event Monitoring (requires Event Monitoring license).
2. For each result with queryCount > 200 in 30 minutes, pivot to the 60 minutes before the burst to check for a sobjects enumeration (slower rate, URI ending in /sobjects).
3. Check the source IP against known vendor IP ranges; flag any IP not in the integration vendor's documented IP range.
4. Review the queried Salesforce objects (Account, Contact, Opportunity, Quote) — high-value CRM objects indicate targeted exfiltration.
5. Cross-reference source IP against IOCs in iocs.csv.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| Burst from known integration vendor IP | Verify vendor confirms the activity; if unexplained, revoke token and contact vendor |
| Burst from unknown/VPS IP | Treat as confirmed compromise; escalate to IR immediately |
| No burst > 200/30min | Consider widening threshold to 50/30min; check for slow persistent extraction (H2) |
| Sobjects enumeration preceding burst | Strong indicator; escalate regardless of IP reputation |

## References

- ReliaQuest Threat Spotlight: https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft
- Salesforce Event Monitoring API docs: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/using_resources_event_log_files.htm
