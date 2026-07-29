# PEAK Hunt H1 — Credential confirmed without a successful login (AADSTS700016 + blank app)

**Hypothesis.** An attacker using OAuth client ID spoofing has confirmed one or more valid username+password pairs in our tenant. Because they supply a fake `client_id`, Entra returns **AADSTS700016** ("application not found") *after accepting the credential*, so a working credential is confirmed with **no successful sign-in event** and a **blank `AppDisplayName`**.

**Prepare (data).** Microsoft Entra non-interactive sign-in logs (`AADNonInteractiveUserSignInLogs` in Sentinel, or Graph `signIns` filtered to `nonInteractiveUser`). Verify non-interactive logging is enabled and retained ≥30 days — many tenants ingest only interactive `SigninLogs` and are blind to ROPC.

**Execute (analytic).**
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where ResultType == 700016 and isempty(AppDisplayName) and isnotempty(AppId)
| summarize Attempts=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
            SourceIPs=make_set(IPAddress,20), ASNs=make_set(AutonomousSystemNumber,20), UAs=make_set(UserAgent,10)
    by UserPrincipalName
| order by LastSeen desc
```

**Act.** Treat every returned `UserPrincipalName` as a **confirmed-compromised credential**: force password reset, revoke refresh tokens/sessions, enforce phishing-resistant MFA. Pivot on the source IPs/ASNs to find the wider campaign and any follow-on interactive sign-ins.

**Notes / pitfalls.** A deleted or cross-tenant app can also produce 700016 — the discriminators are the **empty `AppDisplayName`**, the ROPC/non-interactive context, and clustering with 50034/50126 enumeration from the same source. Do not dismiss hits merely because there is no matching successful login — that absence is the technique working as designed.

**Refine.** Feed confirmed UPNs and source ASNs back into H2 (fan-out) and H3 (cloud-ASN ROPC) and into a scheduled analytic; baseline any sanctioned ROPC automation to an allowlist.
