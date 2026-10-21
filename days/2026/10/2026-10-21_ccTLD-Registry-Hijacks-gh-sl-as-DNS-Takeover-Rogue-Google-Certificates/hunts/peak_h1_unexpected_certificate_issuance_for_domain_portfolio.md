# PEAK hunt H1 - Unexpected certificate issuance for the whole domain portfolio, including parked and regional ccTLD names

## Prepare

**Hypothesis.** If an attacker controls the authoritative DNS for one of our domains, even briefly, a public CA can issue a domain-validated certificate that we did not request. Google found the other affected organisations in the 2026 .gh, .sl and .as hijacks by reading Certificate Transparency (CT) logs, so the same logs will show the issuance for our own names.

**Why first.** CT is the only public, after-the-fact evidence the sources agree on. Issuance happens within about 90 minutes of a hijack (iTnews, from CT data), so a daily check closes the detection gap to hours.

**Scope.** Every domain in the registrar and registry inventory, not the CMDB: primary brands, regional ccTLDs, parked domains, retired campaign domains. Include wildcard names.

**Data quality check first.** Confirm the inventory comes from registrar exports. Confirm you have a list of approved issuers and ACME account owners per domain, otherwise every certificate looks unexpected.

## Execute

```bash
# Author: Jarmi
# List certificates logged for one domain in the last 30 days from crt.sh and show issuer and SAN names. Replace example.gh with an inventoried domain.
D=example.gh
curl -s "https://crt.sh/?q=%25.$D&output=json" \
 | python3 -c 'import sys,json,datetime as d; rows=json.load(sys.stdin); cut=(d.datetime.utcnow()-d.timedelta(days=30)).strftime("%Y-%m-%d");
[print(r["entry_timestamp"][:19], r["issuer_name"][:60], r["name_value"].replace("\n",",")) for r in sorted(rows,key=lambda r:r["entry_timestamp"]) if r["entry_timestamp"][:10]>=cut]'
```

```bash
# Author: Jarmi
# Loop the check over an inventory file (one domain per line) and keep a dated copy so tomorrow's run can diff against today's.
mkdir -p ct && for D in $(cat domains.txt); do curl -s "https://crt.sh/?q=%25.$D&output=json" > ct/$D.$(date +%F).json; sleep 2; done
```

## Act

1. For every certificate whose issuer or ACME account is not on the approved list, open a ticket and ask the domain owner whether they requested it.
2. If no one did: file a Certificate Problem Report with the issuing CA, quote the CT log entry, and ask for revocation.
3. Compare the issuance time with DNS history: a certificate minted during a window in which the delegation or A record differed is the signature of this case.
4. Check the same names in the Chrome CRLSet announcements and the issuing CA's revocation notices.

## Knowledge

- CT shows logged certificates only; a certificate the CA never logged is invisible here (the author of the DEV Community commentary makes the same point).
- Count conflict to remember: THN lists at least 12 certificates for Google and YouTube names; iTnews counts 32 across all affected brands. Neither is independently reproduced.
- Keep the dated JSON files: crt.sh results change as logs are re-indexed.
