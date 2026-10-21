# PEAK hunt H2 - Authoritative DNS, delegation and CAA drift across the domain portfolio

## Prepare

**Hypothesis.** A registry or registrar compromise changes the NS records (and so the authoritative answers) of a domain without any change in our own DNS admin console. We will see it only if we compare the delegation held at the registry with the answers given by the authoritative servers, from outside our network, on a schedule.

**Why second.** H1 finds the certificate after the fact; H2 finds the cause while the hijack is still active and before a CA validates anything.

**Scope.** Same inventory as H1. Prioritise domains under small or third-party-operated ccTLDs, where registry security is least known.

**Data quality check first.** Record today's expected NS set, DS records, CAA policy and A/AAAA set for each domain in a file under version control. Without a baseline, drift cannot be seen.

## Execute

```bash
# Author: Jarmi
# Walk the delegation from the root and print the NS set the registry hands out, then ask every listed server for the apex A and CAA records.
D=example.gh
dig +trace +nodnssec NS $D | tail -n 8
for NS in $(dig +short NS $D); do echo "== $NS"; dig +short @"$NS" A $D; dig +short @"$NS" CAA $D; done
```

```bash
# Author: Jarmi
# Compare today's NS set against the baseline file baseline/<domain>.ns (one name per line) and print a diff.
D=example.gh
dig +short NS $D | sort > /tmp/$D.ns.today && diff baseline/$D.ns /tmp/$D.ns.today && echo "NS unchanged" || echo "NS CHANGED"
```

```kql
// Full query in kql/k3. Watched-domain answers that differ from the last 30 days.
DnsEvents
| where TimeGenerated > ago(7d)
| where Name has_any (dynamic(["<add_known_brand_domain_1>"])) and QueryType in ("A", "NS")
| summarize Clients = dcount(ClientIP) by Name, QueryType, IPAddresses
```

## Act

1. If the NS set at the registry differs from the baseline, contact the registrar and the registry out of band, using a number from the contract, not from the console.
2. Enable registry lock (or the equivalent) and DNSSEC for domains where the registry offers it; record the result per domain.
3. Publish a restrictive CAA policy that names your CA and, where the CA supports it, your ACME account and validation methods (RFC 8657). Google stresses CAA does not stop issuance during an active hijack because the attacker controls the zone the CA reads; it limits reuse of cached validation after control returns.
4. After restoration, re-check delegation from several resolvers and re-run H1 for the full hijack window.

## Knowledge

- Cached domain-control validation can outlive the hijack: reuse periods are reported as up to 200 days in the Baseline Requirements (100 days from March 2027, 10 days from March 2029) and 30 days at Let's Encrypt. Treat a restored zone as still exposed for that long unless the CA states otherwise.
- RFC 8657 parameters are honoured only if the CA processes them; the DEV Community commentary says that becomes mandatory from 2027-03-15. Until then a CAA line that names an account is a record, not a gate.
- Registry operators and entry method for the 2026 cases are not public.
