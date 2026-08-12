# PEAK Hunt H2 - Microsoft Graph reconnaissance for payroll/HR/finance roles

## Hypothesis
Following account takeover, the operator enumerates tenant users tied to financial workflows
via Microsoft Graph (`/v1.0/users`, `/v1.0/users?$top=999`, `/v1.0/me`), frequently with an
`axios/1.18.1` user agent, before opening finance-related mail. Defender surfaces this as
"Suspicious Exchange Online Graph Reconnaissance Activity".

## Data sources
- Defender XDR `CloudAppEvents` (Graph activity) / raw Microsoft Graph audit
- Microsoft Defender XDR alert catalogue

## Analytic steps
1. Select Graph events referencing `graph.microsoft.com` in the last 7 days.
2. Filter user agent `axios/` OR request URIs hitting `/v1.0/users`, `/v1.0/me`, or `$top=999`.
3. Keep events whose URIs/search terms include payroll, hr, finance, human resources, benefits, banking.
4. Exclude approved IAM/service-principal callers; correlate remaining actors to the H1 session.

## Expected benign
Legitimate IAM, HR-sync and reporting tools enumerate users broadly. The discriminators are the
axios user agent, finance-term filtering, and an actor/ASN already implicated by session anomalies.

## Related detections
- kql/graph_finance_role_reconnaissance.kql
