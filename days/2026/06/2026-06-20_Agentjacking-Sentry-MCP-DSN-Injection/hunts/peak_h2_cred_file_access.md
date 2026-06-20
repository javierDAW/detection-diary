# PEAK Hunt H2 — Credential File Access by npm Sub-process in AI Agent Lineage

**Hypothesis type:** Collection  
**PEAK phase:** Collection  
**Confidence:** Medium-High  
**Priority:** High (direct indicator of data staging for exfiltration)

## Hypothesis

An attacker-controlled npm package, executed by an AI coding agent via injected Sentry
MCP content, has read developer credential files (`~/.aws/config`, `~/.npmrc`,
`~/.docker/config.json`, `~/.ssh/id_*`) in preparation for HTTPS exfiltration.
We expect file read events targeting credential paths where the reading process is `node`
and the grandparent process is an AI coding agent binary.

## Data sources

- `DeviceFileEvents` — file read/access events (Defender XDR / Sysmon EID 11)
- `DeviceProcessEvents` — process ancestry (Defender XDR)
- auditd `-a always,exit -F arch=b64 -S open` rules (Linux)
- macOS `EndpointSecurity` framework / ESF log

## Hunt steps

### Step 1 — Windows / Defender XDR (file access in agent lineage)

```kql
let CredPaths = dynamic([
    ".aws\\config", ".aws\\credentials",
    ".npmrc", ".docker\\config.json",
    ".ssh\\id_rsa", ".ssh\\id_ed25519", ".ssh\\id_ecdsa",
    ".config\\gh\\hosts.yml", ".kube\\config"
]);
let AIAgents = dynamic([
    "claude.exe","cursor.exe","windsurf.exe","codex.exe","continue.exe"
]);
// File reads by node children
let FileReads = DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileRead","FileAccessed","FileModified")
| where InitiatingProcessFileName in~ ("node.exe","npx.cmd","node","npx")
| where FolderPath has_any (CredPaths) or FileName in~ (".npmrc","credentials","config.json")
| project
    ReadTs = Timestamp,
    DeviceId, DeviceName, AccountName,
    CredPath = strcat(FolderPath, "\\", FileName),
    NodePID = InitiatingProcessId,
    NodeParent = InitiatingProcessParentFileName,
    NodeParentPID = InitiatingProcessParentId;
// AI agent process launches
let AgentLaunches = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (AIAgents)
| project
    AgentTs = Timestamp,
    DeviceId,
    AgentPID = ProcessId,
    AgentName = FileName;
// Correlate
FileReads
| join kind=inner AgentLaunches on DeviceId
| where NodeParentPID == AgentPID or NodeParent in~ (AIAgents)
| where ReadTs > AgentTs
| project
    ReadTs, DeviceName, AccountName,
    AgentName, AgentTs,
    NodeParent, CredPath
| order by ReadTs desc
```

### Step 2 — Linux (auditd — file opens on credential paths)

```bash
# Configure auditd rule for credential file opens by node processes
sudo auditctl -a always,exit -F arch=b64 -S open,openat \
  -F path=/home/$USER/.aws/config -F comm=node -k ai-agent-cred-access
sudo auditctl -a always,exit -F arch=b64 -S open,openat \
  -F path=/home/$USER/.npmrc -F comm=node -k ai-agent-cred-access
sudo auditctl -a always,exit -F arch=b64 -S open,openat \
  -F path=/home/$USER/.docker/config.json -F comm=node -k ai-agent-cred-access

# Search existing audit logs for matches
sudo ausearch -k ai-agent-cred-access --format text | head -100

# Cross-reference with parent process (look for claude/cursor as ppid)
sudo ausearch -k ai-agent-cred-access -i | grep -B5 'node' | grep 'ppid\|pid\|exe'
```

### Step 3 — macOS (fs_usage / ESF)

```bash
# Monitor file opens by node processes targeting credential paths (requires root)
sudo fs_usage -w -f filesys node | grep -E '(.aws|.npmrc|.docker|.ssh)'

# Check existing OpenBSM audit trail
sudo praudit /var/audit/current | grep -E '(node|npx)' | \
  grep -E '(.aws/config|.npmrc|.docker|.ssh/id_)'
```

### Step 4 — npm cache forensics (offline / DFIR)

```bash
# List recently installed one-off npm packages and compute hashes
find ~/.npm/_npx/ -name 'package.json' -exec sh -c \
  'echo "=== $(dirname $0) ==="; jq ".name,.version,.main" "$0"' {} \; 2>/dev/null

# Hash all JS files in the cache for submission to VirusTotal
find ~/.npm/_npx/ -name '*.js' -exec sha256sum {} \; > /tmp/npx-cache-hashes.txt
cat /tmp/npx-cache-hashes.txt
```

## Triage guide

| Pattern | Verdict | Action |
|---|---|---|
| node reads ~/.aws/credentials AND parent is AI agent | High confidence — active exfiltration | Isolate host; rotate AWS keys immediately |
| node reads ~/.npmrc AND parent is npx (grandparent AI agent) | High confidence | Rotate npm token; check npm publish history |
| node reads ~/.docker/config.json AND beacon follows | Confirmed Agentjacking | Full IR procedure |
| node reads ~/.npmrc during npm install of known package | Likely legitimate | Verify package integrity via npm audit |
| No AI agent ancestor found | Different attack vector | Continue hunting with T1552 broader scope |

## Notes

On macOS, AI agent processes may run under different binary names; check for
`/Applications/Claude.app`, `/Applications/Cursor.app` parent paths in ESF events.
On CI/CD (containerized) environments, the agent binary name may be `claude` or
`cursor` inside a container layer — check container process trees from `crictl` or
`docker inspect`.
