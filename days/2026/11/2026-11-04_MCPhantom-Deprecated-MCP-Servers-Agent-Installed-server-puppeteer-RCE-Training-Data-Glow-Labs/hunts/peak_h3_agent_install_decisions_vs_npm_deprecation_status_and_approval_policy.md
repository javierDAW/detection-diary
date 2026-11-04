# PEAK hunt H3 - Agent install decisions vs npm deprecation status and approval policy

## Prepare

- **Hypothesis:** our AI coding agents install MCP servers without checking npm deprecation status and without a per-service approved server list, so deprecated packages (e.g. the archived `@modelcontextprotocol` reference servers) keep entering the environment even after H1 cleanup.
- **Why first:** Glow Labs found that in 98% of MCPhantom sessions the agent chose the package from training data (the user only asked for "a GitHub MCP"); in one session npm printed "This package is deprecated" and the agent installed anyway. Anthropic archived 13 of its 20 original reference servers; deprecated packages vanish from npm search but `npx` still installs them. The recommended controls are policy controls: one approved server per service, deprecation status in approval criteria, and harness pre-execution hooks.
- **Scope:** all AI coding harnesses in use (Claude Code, Cursor, Codex CLI, Claude Cowork/Desktop), their managed settings, and the last 90 days of MCP install events.

## Execute

**Data sources:** `kql/k1` and `kql/k3` results, harness managed-settings files, npm registry metadata, agent session transcripts where retained.

1. Build the install ledger: every MCP server package seen in k1 / H1, by host and harness.
2. Enrich each package with registry status (generic npm commands):

```bash
# Author: Jarmi
while read -r pkg; do
  dep=$(npm view "$pkg" deprecated 2>/dev/null)
  last=$(npm view "$pkg" time.modified 2>/dev/null)
  printf '%s\t%s\t%s\n' "$pkg" "${dep:-not-deprecated}" "$last"
done < mcp_packages_seen.txt | sort -t$'\t' -k2
```

3. Compare the ledger against the approved list (one server per service, service owner first):

```powershell
# Author: Jarmi
$Approved = Import-Csv .\approved_mcp_servers.csv   # columns: service,package
$Seen     = Import-Csv .\mcp_install_ledger.csv     # columns: host,harness,package,deprecated
$Seen | Where-Object { $_.package -notin $Approved.package -or $_.deprecated -ne 'not-deprecated' } |
  Sort-Object deprecated, package | Format-Table host, harness, package, deprecated -AutoSize
```

4. Check whether harnesses enforce anything before execution: look for managed MCP allow-lists and pre-execution / pre-tool-use hooks in the harness managed settings (locations vary per harness; consult vendor documentation). Record "no hook" as a finding.
5. Transcript review (where retained): search for npm deprecation warnings followed by a successful install.

```bash
grep -rIl -i 'This package is deprecated' ./agent_transcripts/ 2>/dev/null
```

## Act

- **Findings handling:** each unapproved or deprecated install is a policy gap; map it to the harness and team that produced it.
- **Controls to implement:** (1) publish an approved MCP server list with exactly one server per service, preferring the service owner's own server; (2) add "not deprecated on npm" and "actively maintained" to approval criteria; (3) deploy harness pre-execution hooks that block `npx`/`npm exec` of packages not on the list or flagged deprecated; (4) keep `sigma/01` and `kql/k1` as a backstop.
- **Escalation:** repeated installs of server-puppeteer after policy rollout -> engineering leadership plus H2 on the affected hosts.
- **Exit / validation criteria:** approved list published; hooks deployed on all harnesses in scope and tested by attempting `npx -y @modelcontextprotocol/server-puppeteer` in a lab (blocked); k1 shows zero deprecated installs for 30 days.
- **Caveat:** Confidence: low, no technical IOC published. This hunt measures governance coverage, not compromise.
