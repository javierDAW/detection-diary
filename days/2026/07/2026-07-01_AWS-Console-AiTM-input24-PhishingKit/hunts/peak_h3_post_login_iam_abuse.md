# PEAK Hunt H3 — Post-Login IAM Persistence After a Suspicious Console Session

**Hunt ID:** H3  
**Case:** 2026-07-01_AWS-Console-AiTM-input24-PhishingKit  
**Author:** Jarmi  
**Date:** 2026-07-01  
**Technique:** T1098.001, T1136.003, T1550.004  

## Hypothesis

Within seven days, an AWS identity that logged into the console from an anomalous source ASN
performed IAM persistence actions — creating an access key, a user, a login profile, or
attaching an admin policy — from the same source IP.

**Baseline:** After an AiTM replay, an attacker's first goal is durable access that survives
the short-lived console session: a new IAM access key or user gives long-term programmatic
control independent of the stolen browser session. Legitimate IAM administration is performed
by a small, known set of principals from known networks.

**Why this matters:** The console session captured by AiTM expires; the access key does not.
Catching the key/user creation is the difference between containing one session and chasing a
persistent foothold.

## Data Sources

- AWS CloudTrail: management events (Sentinel AWSCloudTrail)
- AWS IAM Access Analyzer / Access Advisor
- IOCs of the day for the anomalous source IPs identified in H1

## Hunt Query (KQL — Sentinel AWSCloudTrail)

```kql
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventName in ("CreateAccessKey","CreateUser","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","AttachRolePolicy")
| project TimeGenerated, UserIdentityArn, EventName, SourceIpAddress, UserAgent, RequestParameters
| order by TimeGenerated desc
```

## Analysis Steps

1. Run the query; enumerate IAM mutation events and their source IPs.
2. Cross-reference each SourceIpAddress with the anomalous ASNs/IPs surfaced in H1.
3. For any match, list the artifacts created (new key ID, new username, attached policy ARN).
4. Check whether the acting principal legitimately performs IAM administration; a developer
   identity creating admin users is a strong compromise signal.
5. Contain: disable/delete the created access keys and users, detach the policies, and rotate
   the compromised principal's credentials. Review CloudTrail for data-plane actions
   (s3:GetObject bursts, secretsmanager:GetSecretValue) from the new key.

## Expected Findings / Triage

| Finding | Action |
|---|---|
| Key/user creation from H1 anomalous IP | Confirmed persistence; delete artifacts, rotate principal, full IR |
| IAM mutation by a principal that never does IAM admin | High suspicion; validate with the owner, contain if unexplained |
| Admin policy attached to a fresh user | Critical; disable immediately and hunt for data-plane exfiltration |
| No IAM mutations | Still review read-only recon (GetCallerIdentity, ListBuckets) from the session |

## References

- Datadog Security Labs — Behind the console: https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/
- MITRE T1098.001 Additional Cloud Credentials: https://attack.mitre.org/techniques/T1098/001/
