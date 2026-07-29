# PEAK Hunt H3 — ROPC from a cloud-provider ASN / scripted User-Agent

**Hypothesis.** OAuth client ID spoofing is executed through the ROPC (password) grant from cloud-hosting infrastructure (UNK_pyreq2323 from AWS with `python-requests/2.32.3`; UNK_OutFlareAZ from Cloudflare). Legitimate ROPC use is near-zero in a modern tenant, so ROPC from a datacenter ASN or a scripted UA is high-signal on its own.

**Prepare (data).** `AADNonInteractiveUserSignInLogs` with `ClientAppUsed`/`AuthenticationProtocol`, `UserAgent`, `AutonomousSystemNumber`, `IPAddress`. Enrich `AutonomousSystemNumber`/`IPAddress` with hosting-provider classification (AWS, Cloudflare, other VPS) where available.

**Execute (analytic).**
```kql
let scriptedUA = dynamic(["python-requests","python-urllib","okhttp","Go-http-client","curl"]);
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed has "Other clients" or tostring(AuthenticationProtocol) has "ropc"
| where UserAgent has_any (scriptedUA) or AutonomousSystemNumber in (<add_known_cloud_asn_list>)
| summarize TargetedUsers=dcount(UserPrincipalName), Attempts=count(), DistinctApps=dcount(AppId),
            ResultTypes=make_set(ResultType,12), UAs=make_set(UserAgent,8)
    by IPAddress, AutonomousSystemNumber, bin(TimeGenerated, 1h)
| where TargetedUsers > 25   // tune to baseline
| order by TargetedUsers desc
```

**Act.** Block the offending ranges, then move to eradicate the root cause: **disable the ROPC grant / legacy authentication tenant-wide** via Conditional Access ("Other clients") or the ROPC-specific control. Re-run H1 afterwards to confirm no new 700016-on-blank-app events appear.

**Notes / pitfalls.** Some sanctioned automation legitimately uses ROPC against a registered app; allowlist those service accounts and source IPs before enforcing a block. ASN enrichment quality varies by data source — treat the UA and the blank-app fan-out (H2) as corroborating signals.

**Refine.** Maintain a living allowlist of sanctioned ROPC service principals/IPs; alert on any ROPC outside it. Track whether blocking ROPC drops the 50053 smart-lockout rate as a recovery metric.
