# PEAK Hunt H2 — Spoofed-app fan-out (many distinct AppIds from one source)

**Hypothesis.** A source (IP/UA) is spraying/enumerating our tenant while fragmenting attempts across **many distinct fictional `client_id` values** to defeat per-application detection and rate limiting. Each event carries a blank `AppDisplayName` because the client_id does not resolve to a registered app.

**Prepare (data).** `AADNonInteractiveUserSignInLogs` (Sentinel) with `AppId`, `AppDisplayName`, `ResultType`, `IPAddress`, `AutonomousSystemNumber`, `UserAgent`. Baseline the normal count of distinct AppIds per source IP per hour (legitimate sources use a small, stable set).

**Execute (analytic).**
```kql
let window = 1h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType in (50034, 50126, 50053, 700016)
| where isempty(AppDisplayName) and isnotempty(AppId)
| summarize DistinctApps=dcount(AppId), TargetedUsers=dcount(UserPrincipalName), Attempts=count(),
            ErrCodes=make_set(ResultType,10), UAs=make_set(UserAgent,10)
    by IPAddress, AutonomousSystemNumber, bin(TimeGenerated, window)
| where DistinctApps >= 20   // tune to baseline
| order by DistinctApps desc
```

**Act.** For high fan-out sources, block the source range at the identity/CA layer, capture the AppId set and UA, and cross-reference the targeted users with H1 for any confirmed credentials. Note whether the actor **reuses** a spoofed AppId across a handful of users (UNK_pyreq2323 reused each across up to 12) or uses a **unique** UUIDv4 per request (UNK_OutFlareAZ) — this fingerprints the cluster.

**Notes / pitfalls.** Conditional Access policies scoped to named applications will NOT have fired on these events; do not rely on "no CA hit" as reassurance. Cardinality thresholds cannot be expressed in Sigma, so this fan-out logic lives in KQL/SIEM aggregation.

**Refine.** Convert to a scheduled analytic with a per-source `dcount(AppId)` threshold and alphabetical-username-ordering heuristic; promote confirmed clusters into a watchlist of actor ASNs.
