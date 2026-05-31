# H2 — Password spray against the single-password SCADA gateway login

## Frame

Prepare-Execute-Act-Know hunt. Claude generated credential lists (default +
environment-specific + reused-from-other-victims) and directed two rounds of
automated password spraying against the vNode SPA's single-password login. Both
failed at SADM, but the *attempt* is highly detectable in the gateway's auth
logs and is the moment the IT-OT boundary is tested.

## Hypothesis

If credential lists were sprayed against the gateway, its login path shows a
burst of authentication failures with low password cardinality and high account
cardinality from a single source within a short window.

## Expected benign baseline

A few failed logins from a forgetful operator or a misconfigured client are
normal. A vulnerability scanner can also generate failures — distinguish by
whether many distinct usernames are tried with few passwords from one source.

## Action on match

Confirm whether any spray attempt succeeded (look for a 200/redirect after the
failure burst), rotate gateway credentials, lock the login to the engineering
jump host, and pivot to H1 (who reached the gateway) and H3 (AI tooling).

## Query — Sentinel (gateway web/proxy Syslog)

```kql
Syslog
| where TimeGenerated > ago(30d)
| where SyslogMessage has "<add_known_scada_gateway_host>"
| where SyslogMessage has_any ("401", "403", "Unauthorized", "login failed", "authentication failure")
| extend SrcIp = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| extend Account = extract(@"user[=:\s\""]+([A-Za-z0-9._\-@]+)", 1, SyslogMessage)
| summarize Failures = count(), Accounts = dcount(Account), AccountList = make_set(Account, 25)
    by SrcIp, bin(TimeGenerated, 10m)
| where Failures > 20 and Accounts > 5
| order by Failures desc
```

## Notes

Many SCADA/IIoT gateways log sparsely; if the gateway itself does not emit auth
events, place a reverse proxy in front of it and log there. The presence of a
single-password (no-username) SPA login is itself a finding — flag it for an MFA
or strong-auth upgrade.
