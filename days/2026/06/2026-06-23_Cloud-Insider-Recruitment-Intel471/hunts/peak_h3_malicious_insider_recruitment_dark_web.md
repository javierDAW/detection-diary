# PEAK Hunt H3 — Internal Signal Correlation: Employee at Risk of Malicious Insider Recruitment

## Hunt metadata

| Field | Value |
|---|---|
| Hunt ID | H3 |
| Hypothesis | Employees with pending termination or disciplinary action who show anomalous data-access patterns (bulk download, new cloud sync endpoints, USB mass storage attachment) are either engaged in self-initiated theft or have been recruited by underground actors matching the samsepi0l/betway/Finduser profile |
| PEAK phase | Execute |
| MITRE | T1078, T1530, T1052.001 Exfiltration over USB, T1567.002 |
| Primary data source | Defender XDR DeviceFileEvents + DeviceNetworkEvents + HR system watchlist |
| Reference | Intel 471 Cloud Insider Threat Report 2026; Intel 471: 771/1002 incidents occurred while insider still employed |
| Author | Jarmi |
| Date | 2026-06-23 |

## Hypothesis rationale

Intel 471 documents that 19 of 41 tracked underground posts in 2025 were actors actively seeking insiders — not waiting for employees to self-present. The samsepi0l April 4 2026 auction demonstrated that insiders with "master admin + Slack + Okta access" are specifically sought. The human recruitment vector targets employees who hold privileged access and may be financially motivated or in a grievance state. This hunt combines HR data (employees on PIP, notice period, disciplinary investigation) with endpoint telemetry to surface individuals who are exhibiting data-staging or exfiltration behaviors — before data leaves the organisation.

## Data collection

```kql
// Defender XDR: Bulk file copy to removable storage by at-risk employees
let at_risk_devices = dynamic(["<add_device_names_from_hr_watchlist>"]);

DeviceFileEvents
| where TimeGenerated >= ago(14d)
| where DeviceName in~ (at_risk_devices)
| where ActionType in ("FileCreated", "FileCopied")
| where FolderPath startswith "D:\\"  // Removable / USB paths; adjust for env
    or FolderPath startswith "E:\\"
    or FolderPath startswith "F:\\"
| summarize
    FilesCopied = count(),
    DistinctExtensions = dcount(tostring(split(FileName, ".")[-1])),
    FirstCopy = min(TimeGenerated),
    LastCopy = max(TimeGenerated),
    SampleFiles = make_set(FileName, 10)
    by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 1h)
| where FilesCopied >= 50
| sort by FilesCopied desc
```

```kql
// Defender XDR: New cloud sync / file-share endpoints for at-risk employees
let at_risk_devices = dynamic(["<add_device_names_from_hr_watchlist>"]);
let personal_cloud_domains = dynamic([
    "dropbox.com", "box.com", "mega.nz", "wetransfer.com",
    "gofile.io", "anonfiles.com", "filetransfer.io"
]);

DeviceNetworkEvents
| where TimeGenerated >= ago(14d)
| where DeviceName in~ (at_risk_devices)
| where RemoteUrl has_any (personal_cloud_domains)
    or RemoteHostname has_any (personal_cloud_domains)
| project TimeGenerated, DeviceName, RemoteHostname, RemoteUrl,
          RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated desc
```

## Analysis

For each alert returned:
1. Verify HR status — confirm employee is on watchlist for cause (PIP, notice, investigation).
2. Correlate with badge access logs: was the employee present in the building at the time of the file copy?
3. Review Slack/Teams logs for any communications referencing grievances, financial distress, or contact with external parties offering "freelance opportunities."
4. Cross-reference with Data Loss Prevention (DLP) alerts — is the file content classified?
5. If USB copy confirmed with classified data: immediately notify HR, Legal, and Security leadership; do NOT alert the employee — preserve evidence first.

## Expected output

A list of at-risk employees with corroborated anomalous data-movement behavior, ranked by volume and data sensitivity.

## Escalation criteria

- Any confirmed bulk copy to USB or personal cloud by employee on active termination notice = preserve endpoint image before revocation; initiate IR.
- Any anomalous sign-in from a non-corporate IP for an employee with administrative access = check for underground recruitment correlation; escalate to CISO.
- Pattern of after-hours access + bulk download + personal cloud upload = near-certain insider exfiltration; engage Legal before any employee contact.
