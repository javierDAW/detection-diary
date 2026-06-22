# PEAK Hunt H1 — BITTER Infrastructure Discovery via JARM + ASN 44901 Pivot

**Hypothesis:** If BITTER reuses ASN 44901 hosting with JARM fingerprint `15d3fd16d29d29d00042d43d0000001ae0802418786940cae38f1d9eed5b9b` for C2 and staging, then passive DNS and internet scan datasets will surface new domains sharing that fingerprint not yet in public blocklists — enabling proactive blocking before victim interaction.

**MITRE:** T1583.001 (Acquire Infrastructure: Domains), T1608.001 (Stage Capabilities: Upload Malware)

**Priority:** High

---

## Prepare

**Scope:** Global internet scan datasets (Shodan, FOFA, Censys); passive DNS (Hunt.io, Farsight DNSDB, VirusTotal); Certificate Transparency logs.

**Data sources required:**
- Shodan API or FOFA query for JARM + ASN combination
- DNSDB / Hunt.io passive DNS for reverse infrastructure lookup
- CT log search (crt.sh) for certificate subject/SAN patterns matching known BITTER domains

**Prerequisites:**
- Access to Shodan or FOFA API with JARM search capability
- DNSDB or equivalent passive DNS subscription

---

## Execute

### Step 1 — JARM + ASN query (Shodan)

```bash
# Search for hosts matching BITTER JARM fingerprint on ASN 44901
curl -s "https://api.shodan.io/shodan/host/search?query=jarm:15d3fd16d29d29d00042d43d0000001ae0802418786940cae38f1d9eed5b9b+asn:AS44901&key=<SHODAN_APIKEY>" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(h['ip_str'], h.get('hostnames','')) for h in d.get('matches',[])]"
```

### Step 2 — FOFA query (replicate Hunt.io pivot)

```
# FOFA query replicating the @volrant136 pivot from Lookout report
jarm="15d3fd16d29d29d00042d43d0000001ae0802418786940cae38f1d9eed5b9b" && title=="403 Forbidden" && asn="44901" && header="Content-Length: 318"
```

### Step 3 — Passive DNS reverse lookup on new IPs

```bash
# For each IP discovered in steps 1-2, query passive DNS for associated domains
# Using Hunt.io API (substitute your endpoint and key)
for IP in <discovered_ips>; do
  curl -s "https://api.hunt.io/v1/dns/reverse?ip=$IP&key=<HUNT_APIKEY>" | python3 -m json.tool
done
```

### Step 4 — CT log search for new domain registration patterns

```bash
# Search crt.sh for certificates issued to BITTER-pattern domains
# Known patterns: *.ai-ae.io, *.com-ae.net, *-app.pro
curl -s "https://crt.sh/?q=%25.ai-ae.io&output=json" | python3 -c \
  "import json,sys; [print(e['name_value'], e['not_before']) for e in json.load(sys.stdin)]" | sort -k2 -r | head -30
```

---

## Analyze

For each discovered domain / IP:
1. Check against current blocklists (Maltrail, URLhaus, ThreatFox) — prioritise any not yet listed.
2. Verify JARM fingerprint matches: `jarmit <IP> 443` (install: `pip install jarm`).
3. Check domain registration date — BITTER typically registers domains within 30 days of use.
4. Resolve domain to IP and check IP reputation (VirusTotal, AbuseIPDB).
5. Fetch HTTP/HTTPS response headers — compare `Content-Length: 318` + `403 Forbidden` pattern.
6. Check for `/v3/` URI response pattern (GET returns 405 Method Not Allowed — expected for POST endpoints).

---

## Act

- **Block immediately:** Any domain resolving to ASN 44901 IP matching JARM + 403/318-byte fingerprint, pending verification.
- **ThreatFox submission:** Submit confirmed new domains with tag `ProSpy:BITTER:hack-for-hire`.
- **Internal blocklist update:** Push to enterprise DNS resolver and NGFW FQDN block policy.
- **Notify Lookout / Access Now:** They maintain the canonical ProSpy IOC list and can validate attribution before public disclosure.

---

## References

- [Lookout ProSpy report — JARM pivot detail](https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire)
- [Hunt.io @volrant136 FOFA fingerprint post](https://x.com/volrant136/status/1923686317252075887)
- [FOFA JARM search](https://en.fofa.info/)
- [crt.sh CT log search](https://crt.sh/)
