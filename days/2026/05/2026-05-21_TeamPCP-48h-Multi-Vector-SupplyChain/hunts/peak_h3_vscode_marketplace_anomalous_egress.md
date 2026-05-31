# PEAK H3 — VS Code Marketplace anomalous egress after extension install or update

**Date:** 2026-05-21
**Author:** Jarmi
**Hypothesis class:** Hypothesis-driven (PEAK)
**Confidence:** medium

## Hypothesis

A developer endpoint in our org installed or auto-updated a VS Code
extension within the last 14 days; within 30 minutes the `Code.exe`
extension-host node child issued egress to a domain not present in the
tenant-curated VS Code telemetry allowlist. Aikido Security tracked
`nrwl.angular-console v18.95.0` (published to the Marketplace at
2026-05-18 12:36 UTC, withdrawn within 11 minutes) as a candidate for the
GitHub corporate breach disclosed on 20-May; the hunt also catches any
future TeamPCP extension compromise that follows the same pattern.

## Why this discriminates

- VS Code extensions have unsandboxed file-system and network access on
  the developer endpoint. A malicious extension is functionally equivalent
  to a backdoor with the developer's full identity privileges.
- The 30-minute install-then-egress join captures both first-installation
  beaconing and auto-update activation.
- The allowlist of VS Code telemetry FQDNs is small and stable per tenant.

## Expected benign vs malicious

| Observation | Benign | Malicious |
|---|---|---|
| Extension folder write under `~/.vscode/extensions/` | Routine | Confirm publisher + version match |
| `Code.exe` → `node.exe` egress | To Marketplace + telemetry only | Anything else within 30 min of install = investigate |
| Egress to `t.m-kosche.com` from any Code.exe child | Never legitimate | Always malicious |
| `nrwl.angular-console v18.95.0` folder present | Never (yanked from Marketplace) | Compromised endpoint |

## Data sources

- Defender XDR: `DeviceFileEvents`, `DeviceProcessEvents`,
  `DeviceNetworkEvents`.
- VS Code extension manifest cache `~/.vscode/extensions/extensions.json`.
- Optional: tenant DLP product with browser/IDE process attribution.

## Hunt queries

### KQL — Defender XDR

See [`../kql/teampcp_vscode_extension_anomalous_egress_after_install.kql`](../kql/teampcp_vscode_extension_anomalous_egress_after_install.kql)
for the full install-then-egress join.

Quick scoped check for the specific Aikido candidate:

```kql
let lookback = 14d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FolderPath has @"\.vscode\extensions\nrwl.angular-console-18.95.0"
        or FolderPath has "/.vscode/extensions/nrwl.angular-console-18.95.0"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

### PowerShell — Windows developer endpoints

```powershell
Get-ChildItem -Path "$env:USERPROFILE\.vscode\extensions\" -Filter "nrwl.angular-console-*" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like "*18.95.0*" } |
  Select-Object FullName, LastWriteTime
```

### Bash — macOS/Linux developer endpoints

```bash
ls -la ~/.vscode/extensions/nrwl.angular-console-18.95.0 2>/dev/null
# Read manifest to confirm publisher
cat ~/.vscode/extensions/nrwl.angular-console-18.95.0/package.json 2>/dev/null | head -20
```

## Action on match

1. Isolate the endpoint at host firewall level before any user logout
   prompt — the extension persists across IDE restarts.
2. Snapshot the extension folder for downstream YARA + sandbox analysis.
3. Rotate every credential the developer's machine has access to: GitHub
   PATs, npm tokens, PyPI tokens, cloud SSO refresh tokens, SSH keys,
   1Password / Bitwarden vaults.
4. Reimage the endpoint. Do not attempt "extension uninstall + continue
   use" — the malicious extension may have planted additional persistence
   outside the extension folder.
5. Audit the developer's recent git push activity in the last 14 days for
   any operator-introduced commits.
