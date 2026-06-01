# PEAK Hunt H3 — PowerShell download cradles and dead-drop C2 resolution

**Hypothesis:** A host is fetching a remote PowerShell payload via a download
cradle to a file-sharing / paste service, or resolving its C2 from a Telegram
dead drop, consistent with GREYVIBE delivery and LegionRelay.

## Prepare

PhantomRelayLite delivery used cradles such as `WebClient.DownloadString(...) |
powershell -NoProfile -` against compromised domains, and lures hosted archives
on Google Drive and 4sync. Since March 2026 LegionRelay retrieves an encoded C2
address from a hardcoded Telegram channel (each octet decoded by subtracting
`4 + octet_index`), with an embedded fallback URL. The behavioural anchors are:
PowerShell making outbound HTTP, the `DownloadString`/`IEX` cradle shape, and
PowerShell or its children resolving `t.me` / `api.telegram.org`.

- Data sources: `DeviceNetworkEvents`, `DeviceProcessEvents`, proxy/DNS logs.
- Scope: all Windows endpoints, 30-day look-back.

## Execute

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("powershell.exe","pwsh.exe","cmd.exe")
| where ProcessCommandLine has_any ("DownloadString","DownloadData","IEX","Invoke-Expression","ScriptBlock]::Create")
| where ProcessCommandLine has_any ("-NoProfile","-NonInteractive","-W H","-WindowStyle")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("powershell.exe","pwsh.exe")
| where RemoteUrl has_any ("t.me","api.telegram.org","drive.google.com","4sync.com",
                           "pastecode.io","pastes.io","dpaste.org")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp desc
```

## Act

- **Expected benign:** developer tooling and CI agents pull from paste/Google
  Drive; some admins use one-liner installers. Baseline by account and host role.
- **Suspicious:** an interactive user-context PowerShell cradle to a paste site or
  a previously-compromised hosting domain, or PowerShell reaching Telegram APIs on
  a workstation with no Telegram client installed.
- **Pivot:** capture the fetched script, run the YARA pack, and decode any
  Telegram-hosted blob with the `subtract (4 + index)` routine to recover the C2.

Linked detections: `kql/k4_greyvibe_c2_egress.kql`,
`suricata/greyvibe_c2.rules`.
