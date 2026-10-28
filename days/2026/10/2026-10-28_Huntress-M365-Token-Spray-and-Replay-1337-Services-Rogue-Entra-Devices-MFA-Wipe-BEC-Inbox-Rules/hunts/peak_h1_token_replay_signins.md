# PEAK hunt H1 - replayed sessions from hosting infrastructure with scripted clients

## Prepare

**Hypothesis.** If our tenant was in the Huntress victim set (79 organizations, 2026-07-14 to 2026-09-22), the sign-in logs hold successful or CA-blocked sign-ins from the 193.26.115.0/24 block, from the four related addresses, or by the Office and Authentication Broker client IDs with a bare `node` or `Mozilla/5.0` user agent.

**Why first.** It is the entry signal and needs only Entra sign-in logs, including the non-interactive table, which many teams do not retain or query. Huntress separated targets by whether the credential was valid, not by spray volume, so AADSTS53003 rows matter as much as successes.

**Scope.** Interactive and non-interactive sign-ins for 90 days (the campaign ran 10 weeks). Record the oldest available log date; if it starts after 2026-07-14, say the answer covers only that window.

## Execute

```kql
// Author: Jarmi
// Sentinel: replay-host and scripted-client sign-ins (full query in kql/k1).
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where ipv4_is_in_range(IPAddress, "193.26.115.0/24") or (AppId in ("d3590ed6-52b3-4102-aeff-aad2292ab01c","29d9ed98-a469-4536-ade2-f981bc1d605e") and UserAgent in~ ("node","Mozilla/5.0"))
| summarize First=min(TimeGenerated), Last=max(TimeGenerated), Successes=countif(ResultType=="0"), Blocked=countif(ResultType=="53003") by UserPrincipalName, IPAddress
```

## Act on

- Any success from the published block, or a scripted-client success on Office/Broker: treat the account as compromised. Revoke sessions, then go to H2 for persistence before resetting the password.
- Only AADSTS53003 rows: the credential is valid and Conditional Access held. Reset the credential, review exclusions in the policy and keep the account under watch.
- AADSTS50133 from the same session several times: the stolen session was revoked or invalid; confirm what the user did after the first prompt.

## Knowledge

A password reset does not remove attacker devices, MFA methods or the access token (about 90 minutes). Hunt on credential validity, not volume.
