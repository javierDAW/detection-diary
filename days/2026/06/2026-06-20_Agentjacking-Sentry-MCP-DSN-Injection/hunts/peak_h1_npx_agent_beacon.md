# PEAK Hunt H1 — Outbound Beacon from npx Child of AI Coding Agent

**Hypothesis type:** Execution  
**PEAK phase:** Execution  
**Confidence:** Medium  
**Priority:** High (novel attack class; no prior hunting baseline)

## Hypothesis

An attacker has injected a forged error event into a Sentry project via a public DSN.
When a developer asked their AI coding agent (Claude Code, Cursor, Codex) to investigate
Sentry errors, the agent executed an attacker-controlled `npx` package that phoned home
to an external beacon. We expect to find `node` or `npx` processes parented by AI agent
binaries that made outbound HTTPS connections to domains first seen in DNS within the
last 30 days and that are not npm registry CDN endpoints.

## Data sources

- `DeviceProcessEvents` — process ancestry, command line (Defender XDR)
- `DeviceNetworkEvents` — outbound HTTPS from node process (Defender XDR)
- `DnsEvents` / passive DNS — domain first-seen age
- EDR process tree / auditd execve (Linux/macOS)

## Hunt steps

### Step 1 — Identify AI agent parent processes on developer hosts

```kql
// Find all AI agent process instances in last 30 days
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    "claude.exe", "cursor.exe", "windsurf.exe", "codex.exe",
    "claude", "cursor", "windsurf", "codex", "continue.exe"
  )
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Sessions = dcount(InitiatingProcessId)
    by DeviceId, DeviceName, AccountName, FileName
| order by LastSeen desc
```

### Step 2 — Find npx executions within those agent sessions

```kql
let AgentSessions = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    "claude.exe","cursor.exe","windsurf.exe","codex.exe","claude","cursor"
  )
| project DeviceId, AgentPID = ProcessId, AgentTime = Timestamp;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npx","npx.cmd","node.exe","node")
| where ProcessCommandLine has "--yes" or ProcessCommandLine has " -y "
| join kind=inner AgentSessions on DeviceId
| where InitiatingProcessId == AgentPID
    or abs(datetime_diff('second', Timestamp, AgentTime)) < 300
| project Timestamp, DeviceName, AgentPID, ProcessCommandLine, ProcessId
| order by Timestamp desc
```

### Step 3 — Correlate with outbound beacon connections

```kql
let NpxPIDs = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npx","npx.cmd")
| where ProcessCommandLine has "--yes"
| project DeviceId, NpxPID = ProcessId, NpxTime = Timestamp;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","node","npx.cmd","npx")
| where RemotePort == 443
| join kind=inner NpxPIDs on DeviceId
| where InitiatingProcessId == NpxPID or
        abs(datetime_diff('second', Timestamp, NpxTime)) < 300
| where RemoteUrl !has "npmjs.org"
    and RemoteUrl !has "sentry.io"
    and RemoteUrl !has "github.com"
    and RemoteUrl !has "githubusercontent.com"
    and RemoteUrl !has "cloudflare.com"
    and RemoteUrl !has "fastly.net"
| project NpxTime, Timestamp, DeviceName, RemoteUrl, RemoteIPAddress, RemotePort
| order by NpxTime desc
```

### Step 4 — Linux / macOS (auditd)

```bash
# Find npx executions parented by AI agent processes (last 30 days)
sudo ausearch -m execve -ts boot | \
  grep -E '(claude|cursor|codex|windsurf)' -A 10 | \
  grep 'npx\|--yes'

# Check for new outbound connections from node processes in the same timeframe
sudo ss -tnp | grep -i 'node\|npx'
sudo netstat -anp | grep 'node\|npx' | grep ':443'

# Check npm cache for recently-installed one-off packages
ls -lt ~/.npm/_npx/ | head -20
jq '.name,.version' ~/.npm/_npx/*/package.json 2>/dev/null | paste - -
```

## Indicators of compromise to look for

- `node.exe` / `node` making HTTPS POST to novel domains (< 30d old) within 5min of npx execution
- npm cache entries with scoped package names not matching any package.json in the project
- Environment variable dumps or `.aws` file size reports in node process stdout
- `X-Tenet-Security: ResponsibleDisclosure` header in network captures (PoC beacon)

## Expected findings and triage

| Finding | Verdict | Action |
|---|---|---|
| npx --yes with novel package + HTTPS POST to unknown FQDN | High-confidence Agentjacking | Escalate; isolate host; rotate credentials |
| npx --yes with novel package, no network event | Inconclusive | Examine package source in ~/.npm/_npx/ |
| npx --yes with well-known package (e.g., @typescript/...) | Likely legitimate | Close |
| AI agent npx with known package + POST to npmjs CDN only | Legitimate install | Close |

## Notes

The Authorized Intent Chain means this hunt relies on behavioral correlation, not
policy violations. The absence of EDR alerts does not indicate absence of compromise.
