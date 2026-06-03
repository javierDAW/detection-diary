# PEAK Hunt H1 — A/AAAA answers from ip6.arpa zones

**Hypothesis:** A recursive resolver in the estate is returning `A`/`AAAA`
answers for `ip6.arpa` queries, indicating a host resolved a reverse-DNS phishing
name backed by a wildcard A record.

## Prepare

By RFC, the `ip6.arpa` namespace serves IPv6 reverse DNS and should return only
`PTR` records (plus zone `NS`/`SOA`). The Infoblox/CloudSEK technique (Feb-Mar
2026) sets a wildcard `A` record on a delegated `ip6.arpa` zone, so a victim who
clicks an image-linked reverse-DNS string resolves the name to a routable phishing
IP. Any `A`/`AAAA` answer in this namespace is an RFC violation — CloudSEK rates
the false-positive rate at 0%.

- Data sources: recursive resolver query+answer logs (BIND `query.log`, Windows
  DNS Analytical, Umbrella/Infoblox), Sentinel `DnsEvents`, Sysmon EID 22.
- Scope: all internal resolvers and Windows endpoints, 90-day look-back.

## Execute

```kql
DnsEvents
| where TimeGenerated > ago(90d)
| where Name endswith ".ip6.arpa"
| where QueryType !in~ ("PTR", "NS", "SOA")
| where isnotempty(IPAddresses)
| summarize Queries=count(), Clients=dcount(ClientIP),
            SampleNames=make_set(Name, 25) by QueryType
| order by Queries desc
```

```bash
# Resolver-side, BIND query log
grep -E 'ip6\.arpa' /var/log/named/query.log \
  | grep -E 'IN[[:space:]]+(A|AAAA)' | grep -vE 'IN[[:space:]]+PTR' | sort -u
```

## Act

Any result is high-confidence malicious. Pivot the client IP to proxy/firewall to
confirm an actual HTTP session (click) vs a stray lookup, block the resolved
phishing IP, and deploy an RPZ rule that NXDOMAINs non-`PTR` answers for
`*.ip6.arpa`. Escalate clicked endpoints to the credential-harvest IR path.
