# PEAK Hunt H2 — AWS-Support Lures Delivered via SendGrid / Nimbu

**Hunt ID:** H2  
**Case:** 2026-07-01_AWS-Console-AiTM-input24-PhishingKit  
**Author:** Jarmi  
**Date:** 2026-07-01  
**Technique:** T1566.002, T1656  

## Hypothesis

Inbound email delivered through a legitimate ESP (SendGrid, Nimbu) contains a link to an AWS
or SendGrid look-alike host, or a URL carrying the input_24 parameter, and was delivered to a
software engineer or engineering leader in the last 14 days.

**Baseline:** The operators abuse reputable senders to pass SPF/DKIM/DMARC, so sender
authentication alone is not protective. The discriminator is the URL destination host, not the
envelope sender. Legitimate AWS mail links to first-party amazonaws.com / aws.amazon.com hosts.

**Why this matters:** Because the kit gates rendering on a per-recipient encrypted blob, the
lure is the earliest artifact defenders can catch before any credential is submitted. Finding
the mail lets you warn the exact targeted users.

## Data Sources

- Microsoft Defender XDR: EmailEvents + EmailUrlInfo
- Secure email gateway URL rewrite / click logs
- IOCs of the day (iocs.csv) for the host list

## Hunt Query (KQL — Defender XDR)

```kql
let phishHosts = dynamic([
    "us-west-login.com","us-east-prod.com","loginportal-aws.com",
    "switch-sglogin.com","uslogin-prodsg.com","us-west-prod.com"]);
let urls =
    EmailUrlInfo
    | where Url has_any (phishHosts) or Url contains "input_24="
    | project NetworkMessageId, Url;
EmailEvents
| where Timestamp > ago(14d)
| join kind=inner urls on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromDomain, Subject, Url
| order by Timestamp desc
```

## Analysis Steps

1. Run the query; list recipients, senders and the linked hosts.
2. Confirm the sending domain resolves to SendGrid/Nimbu shared infrastructure (expected — the
   abuse is of a legitimate ESP, so do not treat that as exculpatory).
3. For each recipient, check H1 to see whether they subsequently resolved the phishing host.
4. Pull the raw message to recover the full input_24 URL; the encrypted blob confirms
   per-recipient targeting.
5. Warn targeted users directly; force credential + MFA rotation for anyone who clicked.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| Mail with look-alike link delivered, recipient clicked | Escalate to H1; revoke AWS session, rotate credentials |
| Mail delivered, no click recorded | Warn recipient, block domains, monitor for delayed access |
| input_24 URL present | Confirms targeted campaign; preserve message for IR + report to AWS/ESP abuse |
| No results | Check whether ESP mail bypasses inspection; add the host list to gateway blocklist |

## References

- Datadog Security Labs — Behind the console: https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/
- NVISO — Shedding light on the PoisonSeeds phishing kit: https://blog.nviso.eu/2025/08/12/shedding-light-on-poisonseeds-phishing-kit/
