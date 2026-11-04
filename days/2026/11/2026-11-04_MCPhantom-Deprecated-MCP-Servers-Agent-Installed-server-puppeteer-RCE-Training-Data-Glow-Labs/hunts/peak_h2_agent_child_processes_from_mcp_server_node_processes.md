# PEAK hunt H2 - Agent child processes from MCP server node processes

## Prepare

- **Hypothesis:** a deprecated MCP server running on a developer host (server-puppeteer first) has been driven by prompt injection to start an arbitrary process instead of the browser, producing shell, script-host or download-utility children of the `node` process hosting that server.
- **Why first:** Glow Labs describes this exact server-puppeteer RCE mechanism: the developer's "allow web browsing" approval ends up covering the arbitrary command, so the harness does not stop it. The maintainers archived the server in May 2025 and closed the report; no fix is coming and no CVE/GHSA id exists. The payload, code path and affected versions were NOT published, so this hunt is behavioral.
- **Scope:** hosts identified in H1 plus any host where `kql/k1` shows deprecated MCP server execution; last 90 days.

## Execute

**Data sources:** Defender XDR `DeviceProcessEvents`, `DeviceNetworkEvents`; Sysmon EID 1 / auditd `execve` on Linux/macOS.

1. Run `kql/k2_shell_children_of_deprecated_mcp_server_node_processes.kql` (Windows children of `node.exe` whose command line names a deprecated server).
2. Baseline what the puppeteer server normally spawns (it should be a browser binary) and flag everything else:

```kql
// Author: Jarmi
DeviceProcessEvents
| where Timestamp > ago(90d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has "server-puppeteer"
| summarize Count = count(), Hosts = dcount(DeviceName), SampleCmd = any(ProcessCommandLine) by FileName
| order by Count asc
```

3. Outbound connections made by those children (rarity first):

```kql
// Author: Jarmi
let Kids = DeviceProcessEvents
| where Timestamp > ago(90d)
| where InitiatingProcessFileName =~ "node.exe" and InitiatingProcessCommandLine has "server-puppeteer"
| where not(FileName has_any ("chrome","chromium","msedge"))
| distinct DeviceId, ProcessId, FileName;
DeviceNetworkEvents
| where Timestamp > ago(90d)
| join kind=inner Kids on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| summarize Conns = count(), Hosts = dcount(DeviceName) by RemoteUrl, RemoteIP, FileName
| order by Hosts asc, Conns asc
```

4. Linux / macOS live check of the running process tree:

```bash
# Author: Jarmi
for pid in $(pgrep -f 'server-puppeteer|@modelcontextprotocol/server-'); do
  echo "== MCP server pid $pid: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null || ps -o command= -p "$pid")"
  pgrep -P "$pid" | xargs -r ps -o pid,ppid,user,command -p
done
```

```bash
# auditd: execve events whose parent is an MCP server node process (requires -a always,exit -F arch=b64 -S execve)
ausearch -sc execve -i --start this-week | grep -B2 -A2 -E 'server-puppeteer|modelcontextprotocol'
```

## Act

- **Findings handling:** a shell, script host or download LOLBin child of a deprecated MCP server process is suspicious until explained. Pull the agent session transcript for that time window and look for the web content the agent browsed just before the spawn (likely injection vector).
- **Escalation:** confirmed unexpected child -> DFIR: isolate host, collect process tree, npx cache, MCP configs and agent transcripts; rotate any tokens available to the agent (GitHub, cloud, database) since the agent runs with the developer's privileges.
- **Exit / validation criteria:** every child process of deprecated MCP server processes in scope is explained, or the deprecated server is removed (H1); `sigma/03` and `kql/k2` deployed with a tuned exclusion for the npx install wrapper.
- **Caveat:** Confidence: low, no technical IOC published. Glow Labs reported no exploitation in the wild.
