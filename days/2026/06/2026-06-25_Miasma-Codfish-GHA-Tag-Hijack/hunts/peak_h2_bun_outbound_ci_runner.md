# PEAK Hunt H2 — Bun Runtime Outbound Connections from Self-Hosted CI Runners

**Hunt ID:** H2  
**Hypothesis:** At least one self-hosted GitHub Actions runner in the environment has
executed the `bun` JavaScript runtime and made outbound HTTPS connections to
`api.github.com`. Bun is not a standard CI runtime; its presence on a runner indicates
either an explicitly declared workflow step or a malicious composite action that
installed it via `oven-sh/setup-bun`. The combination of Bun execution + GitHub API
commit search polling is the Miasma dead-drop C2 fingerprint.

**PEAK phase:** Execution  
**Data sources:** EDR process telemetry (Defender for Endpoint / CrowdStrike), network
flow logs (firewall / NDR), Sysmon EID 1 + EID 3 on self-hosted runners  
**Skill level:** Intermediate  

## Procedure

### Step 1 — Find Bun process executions on runner hosts

```kql
// Defender XDR: Bun process on any device (runner or developer workstation)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bun", "bun.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

```bash
# Sysmon EID 1 query (PowerShell on self-hosted Windows runner)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match "bun" } |
    Select-Object TimeCreated, Message | Format-List
```

### Step 2 — Correlate with outbound GitHub API calls

```kql
// Defender XDR: Bun making network connections
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("bun", "bun.exe")
| where RemoteUrl contains "api.github.com"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Step 3 — Check if Bun is declared in workflow files

For each runner host where Bun was found, identify which workflow triggered the run and
verify whether the workflow file explicitly declares `oven-sh/setup-bun`:

```bash
# In the repo that triggered the run
grep -r "oven-sh/setup-bun" .github/workflows/

# If NOT found in workflow files but Bun executed: the action.yml of a third-party
# action likely installed it silently (malicious composite pattern)
```

### Step 4 — Check the specific GitHub API URI path

```bash
# Look for /search/commits in network logs
# On Linux self-hosted runner, check auditd or tcpdump capture
tcpdump -nn -A 'host api.github.com and port 443' 2>/dev/null | grep -i "search/commits"

# Or query firewall logs for destination 140.82.112.0/20 port 443
# Filter source process PID to bun/node
```

## Expected outcome

- **Clean:** Bun is only found on runners where it is explicitly declared in the
  workflow YAML, and outbound API calls go to standard GitHub endpoints
  (`/repos/`, `/orgs/`, `/graphql`).
- **Compromise indicator:** Bun is present but not declared in workflow YAML, or Bun
  makes connections to `api.github.com/search/commits`. Treat as active compromise:
  collect runner logs, revoke all credentials in scope, identify all runs since
  the action was hijacked.

## Notes

- GitHub hosted runners are ephemeral (per-run VMs); process telemetry is only available
  if you have GitHub Actions OIDC-based logging forwarded to your SIEM or if you use
  step-security/harden-runner (which blocks unexpected network egress).
- Self-hosted runners are persistent and easier to instrument with EDR/Sysmon.
- False-positive control: check `package.json` / `bun.lockb` in the target repo for
  Bun as a declared runtime dependency.
