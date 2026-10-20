# PEAK hunt H2 - Callback phishing and lookalike IT domains

## Prepare

**Hypothesis.** If the MAIN access model (bulk email with a PDF that shows a support number) or the targeted model (a scheduled call to a named executive from "the IT department") is aimed at the organisation, then mail arrives from a domain that combines the organisation name with IT-themed words (-it.com, it-.com, -law.com patterns per GuidePoint), carries a PDF with a phone number and no link, and is followed by an inbound call from a disposable number.

**Why second.** The call and the lookalike domain are the only parts of the intrusion that exist before a tool is installed, so they are the earliest defensible signal.

**Scope.** All inbound mail for 30 days to the scoped endpoints and their assistants; telephony records (PBX, Teams call logs) for the same users.

**Data quality check first.** Confirm that EmailEvents keeps sender domain and attachment type, and that the telephony platform can export inbound calls with the caller number and the target user.

## Execute

```kql
// Full query in kql/k4. Lookalike sender domains that contain your organisation name.
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromDomain matches regex @"(?i)[a-z0-9-]*-(it|law)\.com$"
| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress) by SenderFromDomain
```

```bash
# Author: Jarmi
# Newly seen domains from a DNS or proxy log export (one domain per line) that contain the organisation name and an IT word.
grep -iE '(^|\.)(orgname)[a-z0-9-]*(it|helpdesk|support)[a-z0-9-]*\.com$' dns_domains.txt | sort | uniq -c | sort -rn | head -30
```

## Act

1. Pull every PDF attachment from a flagged sender and read the visible phone number; compare the number with other reports from your peers (ISAC, bar association).
2. Check telephony logs for inbound calls to the same recipients in the hour after delivery; look for calls booked in advance with an executive's assistant.
3. Block the sender domain and brief the recipients that IT will not cold-call for a session or a code.
4. Register your own lookalike variants and set up newly-registered-domain monitoring that watches your name plus it, support and helpdesk.

## Knowledge

- Record the domains, the phone numbers and the recipients; share them with the FBI and with peers.
- Do not assume that the group needs malware. GuidePoint reports none in the chats.
- The MAIN model was reported as degraded by June 2026, while the targeted model continued to the end of the data.
