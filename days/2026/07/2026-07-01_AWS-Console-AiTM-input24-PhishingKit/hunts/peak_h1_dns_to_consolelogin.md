# PEAK Hunt H1 — Phishing-Domain Resolution Followed by AWS ConsoleLogin

**Hunt ID:** H1  
**Case:** 2026-07-01_AWS-Console-AiTM-input24-PhishingKit  
**Author:** Jarmi  
**Date:** 2026-07-01  
**Technique:** T1557, T1111, T1078.004  

## Hypothesis

An endpoint or identity that resolved one of the input_24 AiTM phishing domains produced a
successful AWS Management Console login (CloudTrail ConsoleLogin = Success) within 30 minutes
of that resolution.

**Baseline:** Legitimate AWS console access is preceded by DNS to signin.aws.amazon.com /
*.console.aws.amazon.com, never to a NICENIC-registered look-alike. A ConsoleLogin that
follows a look-alike-domain resolution is the AiTM replay signature — the kit captured the
live MFA code and logged in from its own infrastructure.

**Why this matters:** AiTM defeats MFA by relaying the second factor in real time, so the
resulting login looks normal in isolation. The only reliable tell is the temporal join
between the phishing-domain hit and the console login.

## Data Sources

- Microsoft Defender XDR: DeviceNetworkEvents (endpoint DNS/HTTP)
- Corporate DNS/proxy logs (Sigma dns_query / proxy)
- AWS CloudTrail: ConsoleLogin events (Sentinel AWSCloudTrail)

## Hunt Query (KQL — Defender XDR endpoint side)

```kql
let phish = dynamic([
    "us-west-login.com","aws.us-west-login.com","aws-central.us-west-login.com",
    "us-east-prod.com","aws.us-east-prod.com","loginportal-aws.com"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (phish)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, RemoteUrl
| order by Timestamp desc
```

## Hunt Query (KQL — Sentinel AWSCloudTrail side)

```kql
AWSCloudTrail
| where TimeGenerated > ago(14d)
| where EventName == "ConsoleLogin"
| extend Result = tostring(parse_json(ResponseElements).ConsoleLogin)
| where Result == "Success"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, AWSRegion
| order by TimeGenerated desc
```

## Analysis Steps

1. Run the endpoint query; collect user/device that hit any phishing host and the hit time.
2. Run the CloudTrail query; for each ConsoleLogin Success, compare its time and identity to
   the phishing-hit list.
3. Flag any ConsoleLogin within 30 minutes of a phishing-domain resolution by the same user.
4. Compare SourceIpAddress ASN/geo to the identity's 30-day login baseline; an AiTM replay
   typically originates from a hosting/VPS ASN, not the user's usual network.
5. If matched, treat the session as compromised: revoke it, rotate credentials, and pivot to
   H3 for post-login IAM abuse.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| ConsoleLogin within 30 min of phishing-domain hit, same user | Confirmed AiTM replay; revoke session, rotate password + MFA, escalate to IR |
| Phishing-domain hit but no ConsoleLogin | Likely blocked/aborted; still rotate the user's credentials as precaution |
| ConsoleLogin from new ASN, no domain hit in DeviceNetworkEvents | Widen DNS source to proxy/firewall logs; endpoint may be unmanaged |
| No matches | Verify DNS logging covers all egress; kit gating means only targeted users see the page |

## References

- Datadog Security Labs — Behind the console: https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/
- MITRE T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
