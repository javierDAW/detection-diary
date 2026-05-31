# PEAK hunts — Semantic Kernel prompt-to-RCE (CVE-2026-26030, CVE-2026-25592)

Author: Jarmi
Date:   2026-05-13
Reference: https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

These hunts apply during the exposure window between when a vulnerable Semantic Kernel version was deployed and when the patched build was installed (Python `semantic-kernel` < 1.39.4, .NET `Microsoft.SemanticKernel` < 1.71.0). The hunts focus on host-side post-exploitation signals because the network layer is dominated by legitimate tool-call traffic.

---

## H1 — Agent host spawning shell or recon LOLBin within a short window after a tool call

### Hypothesis

A Semantic Kernel agent host process (`python.exe`, `python3.exe`, `dotnet.exe`, `node.exe`) spawns a shell, recon, or transfer LOLBin within a short window of model-driven tool calls. This is the canonical post-exploitation primitive after CVE-2026-26030 RCE or any other prompt-injection-to-RCE chain.

### Why this discriminates

A correctly designed agent rarely needs to spawn `cmd.exe`, `powershell.exe`, `certutil.exe`, `whoami.exe`, `nslookup.exe`, `net.exe`, or `nltest.exe` as a child. When the agent runtime sits inside a tool registry where these are not declared as legitimate tools, any such child indicates either (a) an attacker-induced execution, (b) a developer-mode debug session, or (c) a misconfigured RPA-style agent. The third must be allowlisted explicitly.

### Telemetry

Defender XDR `DeviceProcessEvents`, Sysmon EID 1, or any EDR with parent-child telemetry.

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessCommandLine matches regex @"(?i)semantic[\s_\-]?kernel|SKAgent|kernel\.run|SessionsPythonPlugin"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe",
                      "certutil.exe","curl.exe","wget.exe","whoami.exe",
                      "net.exe","nltest.exe","nslookup.exe","dsquery.exe",
                      "bitsadmin.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Expected benign vs malicious

Benign — RPA, devops, or developer-style agents that ship a shell tool. Easy to allowlist by `AccountSid` or by `InitiatingProcessSHA256`. Malicious — production Copilot Studio or M365 Copilot agent hosts emitting `whoami.exe`, `nltest.exe`, `bitsadmin.exe`. Zero hits expected in steady state.

### Action on match

1. Pivot to `DeviceImageLoadEvents` on the same `DeviceName` and `InitiatingProcessId` to confirm `Microsoft.SemanticKernel*.dll` is loaded.
2. Snapshot agent runtime memory (live response `memdump` of agent PID).
3. Treat as suspected compromise — proceed to the IR playbook.

---

## H2 — Agent service principal in Entra ID emits anomalous token requests

### Hypothesis

A service principal or managed identity attached to a Semantic Kernel agent is suddenly emitting `OAuth2.0/v2.0/token` requests for Graph or ARM scopes that are not present in its 30-day baseline. This is the cloud-side post-exploitation primitive when the agent host has a workload identity.

### Why this discriminates

Healthy agents have a small and stable scope catalog. After RCE, an attacker who reaches the host pivots immediately to `IMDS` (instance metadata) or the local MSI token endpoint to obtain a token, then requests new scopes against Graph or other resource endpoints. The scope diversity spike is the cleanest signal.

### Telemetry

Sentinel `SigninLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`. For Defender XDR tenants without Sentinel, use `IdentityLogonEvents` combined with the agent's `AppId`.

### KQL

```kql
// Replace <add_known_agent_appid> with the AppId of the agent service principal
let app = "<add_known_agent_appid>";
let baseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (ago(60d) .. ago(2d))
| where AppId == app
| summarize BaselineScopes = make_set(ResourceDisplayName);
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(2d)
| where AppId == app
| extend NewScope = ResourceDisplayName
| join kind=leftouter baseline on $left.NewScope == $right.BaselineScopes
| where isnull(BaselineScopes)
| project TimeGenerated, IPAddress, NewScope, AppDisplayName, ServicePrincipalName
| sort by TimeGenerated desc
```

### Expected benign vs malicious

Benign — release engineering legitimately added a new tool to the agent and rolled it out, so a new scope appears in the audit trail with a clear correlated release event. Malicious — scope diversity spike outside of release windows, especially toward Graph `Mail.ReadWrite`, `Files.ReadWrite.All`, ARM `Microsoft.Authorization/roleAssignments/*`, or Key Vault.

### Action on match

1. Revoke refresh tokens for the service principal: `Revoke-MgUserSignInSession` or `Update-MgServicePrincipalCredential` to rotate secret.
2. Suspend the agent app in Copilot Studio or Foundry.
3. Audit role assignments granted to the service principal and reduce to the minimum scope the agent actually needs.

---

## H3 — Agent egress to non-allowlisted destinations

### Hypothesis

The agent host process is initiating outbound connections to IPs or domains that are not on the allowlist of model endpoints, tool endpoints, and approved MCP servers. This is the C2 primitive when the operator wires the agent's own HTTP client as the carrier.

### Why this discriminates

A Semantic Kernel agent has a finite egress surface. Model endpoints (Azure OpenAI, OpenAI, Anthropic), declared tool endpoints (one or two HTTP-backed plugins), the telemetry sink, and a sometimes-present MCP server form the entire authorized destination set. Anything else is anomalous. The compromise of the agent runtime turns the agent's HTTP client into a perfect C2 carrier because the egress is indistinguishable from legitimate tool traffic at the transport layer; the only discriminator is the destination.

### Telemetry

Defender XDR `DeviceNetworkEvents`, Sysmon EID 3, or proxy logs that resolve process to destination.

### KQL

```kql
// Allowlist must be maintained per tenant — these are illustrative defaults
let allowed = dynamic([
    "api.openai.com","openai.azure.com","api.anthropic.com",
    "<add_known_agent_tool_fqdn_1>","<add_known_agent_tool_fqdn_2>",
    "login.microsoftonline.com","graph.microsoft.com"
]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("dotnet.exe","python.exe","python3.exe","node.exe")
| where InitiatingProcessCommandLine matches regex @"(?i)semantic[\s_\-]?kernel|SKAgent|kernel\.run"
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| extend host = tolower(coalesce(RemoteUrl, RemoteIP))
| where not(host has_any (allowed))
| summarize Hits=count(), Sample=any(host) by DeviceName, InitiatingProcessSHA256, host
| sort by Hits desc
```

### Expected benign vs malicious

Benign — a release engineer registered a new MCP server or a new tool endpoint and forgot to update the allowlist; correlate with the change-management ticket. Malicious — paste sites, raw IPs without DNS, newly-registered domains, or known commodity C2 infrastructure.

### Action on match

1. Block the host from egress except management VLAN; preserve agent process memory for forensic acquisition.
2. Capture full packet capture (PCAP) of the agent host for the analysis window.
3. Pivot to H1 and H2 to confirm host-side execution and identity-side abuse.
