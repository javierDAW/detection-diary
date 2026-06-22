# PEAK Hunt H3 — Proactive Subdomain Registration Monitoring for BITTER Pattern

**Hypothesis:** If the BITTER hack-for-hire operator creates victim-specific phishing subdomains on-demand from a persistent pool of first-level domains following the `<service-lure>.<digraph>.<TLD>` structural pattern, then monitoring new domain registrations and CT log issuances for this pattern pointing to ASN 44901 will pre-empt delivery before any victim clicks.

**MITRE:** T1583.001 (Acquire Infrastructure: Domains), T1566.002 (Phishing: Spearphishing Link)

**Priority:** High (proactive; disrupts attack before victim interaction)

---

## Prepare

**Scope:** CT log feeds, newly-observed domain feeds (WhoisXML, DomainTools, Spamhaus DBL), passive DNS.

**Data sources required:**
- CT log stream (crt.sh, Certstream, Google Certificate Transparency)
- Newly-registered domain (NRD) feeds
- Passive DNS with ASN resolution

**Structural pattern definitions (BITTER FLD patterns):**
```
Pattern A: <service>.<2-letter>-<2-letter>.<TLD>   # e.g., zoom-meet.eg-uk.com, signal.com-ae.net
Pattern B: <service>-<action>.<digraph>.<TLD>        # e.g., join-secure-call.ai-ae.io
Pattern C: *-app.pro                                  # e.g., botim-app.pro, totok-app.pro
Pattern D: *-pro.<2letter>                            # e.g., totok-pro.io, totok-pro.ae
```

---

## Execute

### Step 1 — Certstream monitor for BITTER domain patterns

```python
#!/usr/bin/env python3
# Author: Jarmi
# Monitor CT log stream (Certstream) for BITTER-pattern domain registrations
# Install: pip install certstream

import certstream
import re
import sys

# BITTER structural patterns
BITTER_PATTERNS = [
    re.compile(r'^[\w-]+\.\w{2}-\w{2}\.(com|net|org|io|me)$'),  # Pattern A
    re.compile(r'^[\w-]+-call\.\w{2}-\w{2}\.io$'),               # Pattern B (call lure)
    re.compile(r'^[\w-]+-app\.pro$'),                             # Pattern C
    re.compile(r'^(signal|totok|botim|whatsapp|telegram)[-_]pro\.\w{2,3}$'),  # Pattern D
]

def callback(message, context):
    if message['message_type'] == 'certificate_update':
        domains = message['data']['leaf_cert']['all_domains']
        for domain in domains:
            for pat in BITTER_PATTERNS:
                if pat.search(domain.lower()):
                    print(f"[MATCH] {domain} — Pattern: {pat.pattern}")
                    sys.stdout.flush()

certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
```

### Step 2 — NRD feed filter (daily batch)

```bash
# Filter daily NRD feed for BITTER structural patterns
# Assumes NRD feed is available as line-delimited domain list
# Source: WhoisXML NRD daily feed or equivalent

NRD_FEED="/tmp/nrd_$(date +%Y%m%d).txt"

grep -E "^[\w-]+\.\w{2}-\w{2}\.(com|net|org|io|me)$" "$NRD_FEED" > /tmp/bitter_pattern_candidates.txt
grep -E "^[\w-]+-app\.pro$" "$NRD_FEED" >> /tmp/bitter_pattern_candidates.txt
grep -E "^(signal|totok|botim|whatsapp)-pro\.\w{2,3}$" "$NRD_FEED" >> /tmp/bitter_pattern_candidates.txt

wc -l /tmp/bitter_pattern_candidates.txt
cat /tmp/bitter_pattern_candidates.txt
```

### Step 3 — ASN / IP validation for candidates

```bash
# For each candidate domain, resolve to IP and check ASN
while read -r domain; do
  IP=$(dig +short "$domain" | tail -1)
  if [ -n "$IP" ]; then
    ASN=$(curl -s "https://ipinfo.io/$IP/org" 2>/dev/null)
    echo "$domain -> $IP -> $ASN"
  fi
done < /tmp/bitter_pattern_candidates.txt | grep -i "44901\|WEBHOST"
```

### Step 4 — JARM verify on candidate

```bash
# Verify JARM fingerprint for any candidate resolving to ASN 44901
# pip install jarm (or use jarm-standalone)
python3 -c "
import jarm, sys
ip = sys.argv[1]
result = jarm.scan(ip, 443)
print(f'{ip}: {result}')
" <CANDIDATE_IP>
# Expected BITTER: 15d3fd16d29d29d00042d43d0000001ae0802418786940cae38f1d9eed5b9b
```

---

## Analyze

**Positive signal chain (all three = high confidence BITTER):**
1. Domain matches Pattern A, B, C, or D structurally
2. Resolves to IP in ASN 44901
3. JARM fingerprint matches `15d3fd16d29d29d00042d43d0000001ae0802418786940cae38f1d9eed5b9b`
4. HTTP/HTTPS response: `403 Forbidden`, `Content-Length: 318`

**Partial signal (1-2 of above):** flag for manual analyst review; do not auto-block.

**Expected false-positive rate:** Low on ASN+JARM combination; moderate on pattern-only matching (many legitimate services use versioned/regional subdomain patterns).

---

## Act

**Immediate (3/3 signal chain):**
- Submit to ThreatFox with `ProSpy:BITTER:HackForHire` tag
- Block at enterprise DNS resolver (response policy zone)
- Notify Lookout / Access Now for independent validation
- Alert on internal DLP if any corporate user recently received email/message linking to this domain

**Monitoring (1-2 signals):**
- Add to watchlist; re-evaluate after 24h with additional data
- Submit to Passive DNS enrichment for correlated activity

---

## References

- [Lookout ProSpy campaign infrastructure analysis](https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire)
- [Access Now MENA phishing technical report](https://www.accessnow.org/mena-phishing-2026-tech)
- [Certstream CT log streaming](https://certstream.calidog.io/)
- [FOFA JARM fingerprint search](https://en.fofa.info/)
- [WhoisXML NRD feeds](https://newly-registered-domains.whoisxmlapi.com/)
