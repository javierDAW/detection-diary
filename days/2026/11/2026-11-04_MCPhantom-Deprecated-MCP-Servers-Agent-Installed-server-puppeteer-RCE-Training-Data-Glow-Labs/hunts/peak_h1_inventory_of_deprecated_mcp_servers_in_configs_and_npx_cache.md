# PEAK hunt H1 - Inventory of deprecated MCP servers in client configs and the npx cache

## Prepare

- **Hypothesis:** AI coding agents (Claude Code, Cursor, Codex CLI, Claude Cowork) on our developer endpoints have written MCP client configurations that launch archived, deprecated `@modelcontextprotocol` reference servers (server-github, server-postgres, server-slack, server-puppeteer, server-brave-search, server-google-maps, server-gitlab, server-gdrive, server-redis, create-server, server-aws-kb-retrieval, server-everart), and those packages sit in the local npx cache.
- **Why first:** Glow Labs (MCPhantom, 2026-11) saw agents pick these packages from training data in 98% of observed sessions. Help Net Security notes the blind spot: EDR sees a trusted Node process, SCA has no manifest (npx) and no CVE, and software inventory never registers the install. A file-level inventory is the cheapest way to close that gap, and server-puppeteer carries an unpatched high-severity RCE (no CVE/GHSA id, no fix coming).
- **Scope:** all developer workstations, jump boxes and CI runners that run an AI coding harness; last 90 days of EDR telemetry. Config locations below are generic MCP client knowledge, not published by the sources: `.mcp.json` (project) and `~/.claude.json` (Claude Code), `.cursor/mcp.json` and `~/.cursor/mcp.json` (Cursor), `claude_desktop_config.json` (Claude Desktop, under `%APPDATA%\Claude\` on Windows).

## Execute

**Data sources:** endpoint file system (live response / Velociraptor / script push), Defender XDR `DeviceFileEvents` and `DeviceProcessEvents`, npm registry metadata.

1. Windows - search config files for deprecated packages (run per user profile):

```powershell
# Author: Jarmi
$Deprecated = 'server-github','server-postgres','server-slack','server-puppeteer','server-brave-search',
              'server-google-maps','server-gitlab','server-gdrive','server-redis','create-server',
              'server-aws-kb-retrieval','server-everart'
$Pattern = '@modelcontextprotocol/(' + ($Deprecated -join '|') + ')'
$Roots = @($env:USERPROFILE, $env:APPDATA)
Get-ChildItem -Path $Roots -Recurse -Force -File -ErrorAction SilentlyContinue `
    -Include '.mcp.json','mcp.json','claude_desktop_config.json','.claude.json' |
  Select-String -Pattern $Pattern -AllMatches |
  Select-Object Path, LineNumber, @{n='Package';e={$_.Matches.Value -join ','}} |
  Format-Table -AutoSize
```

2. Linux / macOS - same search:

```bash
# Author: Jarmi
PAT='@modelcontextprotocol/(server-(github|postgres|slack|puppeteer|brave-search|google-maps|gitlab|gdrive|redis|aws-kb-retrieval|everart)|create-server)'
grep -rEnH --include='.mcp.json' --include='mcp.json' --include='claude_desktop_config.json' --include='.claude.json' \
  "$PAT" "$HOME" 2>/dev/null
```

3. npx cache - packages already fetched (generic npm knowledge: `~/.npm/_npx/<hash>/node_modules`, on Windows `%LOCALAPPDATA%\npm-cache\_npx`):

```bash
ls -d ~/.npm/_npx/*/node_modules/@modelcontextprotocol/* 2>/dev/null
```

```powershell
Get-ChildItem "$env:LOCALAPPDATA\npm-cache\_npx\*\node_modules\@modelcontextprotocol" -Directory -ErrorAction SilentlyContinue |
  Get-ChildItem -Directory | Select-Object FullName, LastWriteTime
```

4. Confirm deprecation status from the registry for every hit (empty output means not deprecated):

```bash
for p in server-github server-postgres server-slack server-puppeteer server-brave-search server-google-maps \
         server-gitlab server-gdrive server-redis create-server server-aws-kb-retrieval server-everart; do
  printf '%s: ' "@modelcontextprotocol/$p"; npm view "@modelcontextprotocol/$p" deprecated 2>/dev/null || echo "lookup failed"; echo
done
```

5. Fleet view: run `kql/k1_package_runner_invocations_of_deprecated_mcp_servers.kql` and `kql/k3_mcp_client_config_file_writes_inventory.kql`, then join hosts with file-level hits.

## Act

- **Findings handling:** record host, user, config path, package, harness and first-seen date. Treat server-puppeteer hits as priority (unpatched RCE reachable through prompt injection); escalate to H2 for those hosts.
- **Remediation:** replace the deprecated entry with the service owner's own MCP server (e.g. the vendor's official GitHub/GitLab/Slack server), remove the cached package directory, and record the approved server in the inventory.
- **Escalation:** any host where H2 finds shell/LOLBin children of the deprecated server process goes to DFIR triage.
- **Exit / validation criteria:** zero config files and zero npx cache directories referencing the deprecated list across scoped hosts; k1 returns no new executions for 14 days; detections from `sigma/01` and `sigma/02` are deployed.
- **Caveat:** Confidence: low, no technical IOC published. Glow Labs reports no exploitation in the wild; this hunt measures exposure, not compromise.
