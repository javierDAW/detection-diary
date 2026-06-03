# PEAK Hunt H2 — staged ip6.arpa zones delegated to Cloudflare NS

**Hypothesis:** Attackers have pre-staged `ip6.arpa` reverse zones by delegating
them to a commercial CDN nameserver (Cloudflare), ready to activate a wildcard A
record the moment a campaign launches.

## Prepare

CloudSEK's BGP sweep of 127,906 IPv6 prefixes found 384 `ip6.arpa` zones with
Cloudflare NS records but only 2 firing — the other 382 are armed and dormant.
A Cloudflare NS on a reverse zone is operationally abnormal (reverse DNS for a
tunnel allocation is normally served by the broker), so it is a pre-attack tell.
This hunt is proactive: find and pre-block staged infrastructure before it fires.

- Data sources: passive DNS / DNS intelligence feeds, your own resolver telemetry,
  BGP prefix lists (e.g. BGP.tools) converted to `ip6.arpa` nibble zones.
- Scope: external enrichment + 90-day internal resolver look-back.

## Execute

```bash
# For each routed IPv6 /48 (or more specific), compute its ip6.arpa nibble zone and
# query the zone's NS; flag Cloudflare delegation on reverse zones.
while read -r prefix; do
  zone=$(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); \
print(''.join('%x.'%((int(n.network_address)>>(4*i))&0xf) for i in range((128-n.prefixlen)//4,32))+'ip6.arpa')" "$prefix")
  ns=$(dig +short NS "$zone")
  echo "$ns" | grep -qi 'cloudflare.com' && echo "STAGED  $prefix  $zone  -> $ns"
done < ipv6_prefixes.txt
```

```kql
// Internal corroboration - have any staged zones been resolved from inside?
DnsEvents
| where TimeGenerated > ago(90d)
| where Name endswith ".ip6.arpa"
| summarize Lookups=count(), Clients=dcount(ClientIP) by Name
| order by Lookups desc
```

## Act

Add discovered staged zones to a DNS-firewall watchlist and alert on the first
`A`/`AAAA` activation (zero-FP launch signal). Pre-block where policy allows.
Report newly-delegated reverse zones to the hosting provider / Cloudflare abuse.
