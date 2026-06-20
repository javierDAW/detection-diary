# PEAK Hunt H3 — Sentry Ingest Writes from Non-Application Source IPs

**Hypothesis type:** Defense Evasion via Injection  
**PEAK phase:** Initial Access (forged event injection = the first step in kill chain)  
**Confidence:** Low-Medium (requires network visibility to Sentry ingest endpoints)  
**Priority:** Medium (proactive infrastructure hygiene; detect injection before agent acts)

## Hypothesis

An attacker has discovered one or more of the organization's public Sentry DSNs and is
injecting forged error events to poison the Sentry project used by AI coding agents.
We expect to find POST requests to `*.ingest.sentry.io` originating from IP addresses
that are NOT known application servers, CDN edge nodes, CI/CD pipeline IPs, or developer
workstations running the legitimate Sentry SDK.

## Data sources

- Sentry Audit Log API (`GET /api/0/organizations/<org>/audit-logs/`)
- Proxy / NGFW logs with TLS inspection (SNI: `*.ingest.sentry.io`)
- Suricata / Zeek HTTPS flow logs
- AWS / GCP / Azure WAF logs (if Sentry is behind a gateway)

## Hunt steps

### Step 1 — Pull Sentry audit log for recent ingest events

```bash
# Sentry API: list recent events in all projects (requires Admin token)
SENTRY_TOKEN="<add_known_sentry_token>"
SENTRY_ORG="<add_known_org_slug>"

# Get all projects
curl -s "https://sentry.io/api/0/organizations/$SENTRY_ORG/projects/" \
  -H "Authorization: Bearer $SENTRY_TOKEN" | jq '.[].slug'

# For each project, fetch recent events and look for anomalous extra.resolution fields
curl -s "https://sentry.io/api/0/projects/$SENTRY_ORG/<proj-slug>/events/?limit=100" \
  -H "Authorization: Bearer $SENTRY_TOKEN" | \
  jq '.[] | select(.extra.resolution != null) | {id, message, extra}'
```

### Step 2 — Identify injected events by content pattern

```bash
# Search all recent events for ## Resolution or npx in extra fields
curl -s "https://sentry.io/api/0/projects/$SENTRY_ORG/<proj-slug>/events/?limit=100" \
  -H "Authorization: Bearer $SENTRY_TOKEN" | \
  python3 -c "
import sys, json
events = json.load(sys.stdin)
for e in events:
    extra = json.dumps(e.get('extra', {}))
    if any(kw in extra for kw in ['## Resolution', 'npx ', 'curl ', 'wget ', 'bash -c']):
        print(f'SUSPICIOUS EVENT: id={e[\"id\"]} message={e[\"message\"][:80]}')
        print(f'  extra: {extra[:200]}')
"
```

### Step 3 — Identify source IPs from network logs (proxy or Suricata)

```bash
# Suricata / Zeek: find source IPs POSTing to ingest.sentry.io
grep 'ingest.sentry.io' /var/log/suricata/http.log 2>/dev/null | \
  awk '{print $3, $5, $7}' | sort | uniq -c | sort -rn | head -30

# Zeek: HTTP log analysis
zcat /var/log/zeek/http*.gz 2>/dev/null | \
  awk -F'\t' '$8 ~ /ingest\.sentry\.io/ && $7 == "POST" {print $3, $8}' | \
  sort | uniq -c | sort -rn

# Compare source IPs against known application server IPs
# <add_known_app_server_ips> — replace with asset inventory
cat /tmp/sentry_ingest_sources.txt | grep -v -f /tmp/known_app_ips.txt
```

### Step 4 — Cross-reference DSN exposure in public repositories

```bash
# Search public repositories for your organization's Sentry DSNs
# (run from a machine with GitHub search API access)
GITHUB_TOKEN="<add_known_github_token>"
ORG="<add_known_github_org>"

curl -s "https://api.github.com/search/code?q=ingest.sentry.io+org:$ORG" \
  -H "Authorization: Bearer $GITHUB_TOKEN" | \
  jq '.items[] | {path: .path, html_url: .html_url, repo: .repository.full_name}'

# Rotate any DSNs found in public repositories immediately:
# Settings -> Client Keys (DSN) -> Delete old key -> Generate new key
```

### Step 5 — Check for resolution or fix fields in Sentry events containing shell commands

```python
#!/usr/bin/env python3
# Author: Jarmi
# Script to audit Sentry projects for injected resolution fields
import requests, json, re, sys

SENTRY_TOKEN = "<add_known_sentry_token>"
SENTRY_ORG   = "<add_known_org_slug>"
PROJECTS     = ["<add_known_project_slugs>"]

SUSPICIOUS_PATTERNS = [
    r'npx\s+', r'curl\s+', r'wget\s+', r'bash\s+-c', r'sh\s+-c',
    r'##\s*Resolution', r'python3?\s+-c', r'eval\s*\('
]

headers = {"Authorization": f"Bearer {SENTRY_TOKEN}"}

for proj in PROJECTS:
    url = f"https://sentry.io/api/0/projects/{SENTRY_ORG}/{proj}/events/?limit=100"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"ERROR {proj}: {resp.status_code}", file=sys.stderr)
        continue
    for event in resp.json():
        extras = json.dumps(event.get("extra", {}))
        message = event.get("message", "")
        combined = extras + " " + message
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                print(f"[ALERT] Project={proj} EventId={event['id']}")
                print(f"  Message: {message[:100]}")
                print(f"  Extra snippet: {extras[:200]}")
                break
```

## Triage guide

| Finding | Verdict | Action |
|---|---|---|
| Sentry event with ## Resolution + npx command in extra field | Confirmed injection attempt | Delete event; rotate DSN; check agent logs |
| POST to ingest.sentry.io from non-application IP | Possible injection | Audit event content for shell commands |
| DSN in public GitHub repo | DSN exposure | Rotate immediately; audit event log for 30d prior |
| No anomalous events found, no public DSN | No current compromise | Add pre-commit hook for DSN pattern; schedule quarterly re-hunt |

## Notes

The injection step leaves no trace on the victim's infrastructure — it is a write to an
external SaaS platform (Sentry). Detection at this stage prevents the downstream agent
execution entirely. Proactive DSN rotation and Sentry project event auditing are the most
reliable prevention controls available while the AI agent trust-boundary issue remains
unresolved at the architecture level.
