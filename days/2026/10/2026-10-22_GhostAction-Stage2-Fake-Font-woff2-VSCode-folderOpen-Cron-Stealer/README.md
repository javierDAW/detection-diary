---
date: 2026-10-22
title: "GhostAction Stage 2: a stealer hidden in a fake fa-solid-400.woff2 font, launched by a VS Code folderOpen task, with cron persistence"
clusters: ["Unattributed GhostAction operator (Fake Font / PolinRider naming overlap)"]
cluster_country: "Unknown"
techniques_enterprise: [T1566.002, T1528, T1195.001, T1552.001, T1552.004, T1204.002, T1059.007, T1059.004, T1036.008, T1053.003, T1041, T1567]
techniques_ics: []
platforms: [supply-chain, linux, macos, windows]
sectors: [technology, software-development]
category: supply-chain
---

# GhostAction Stage 2: a stealer hidden in a fake fa-solid-400.woff2 font, launched by a VS Code folderOpen task, with cron persistence

## TL;DR

On 2026-10-19 OpenSourceMalware (Paul McCarty), reported by The Hacker News, described a second stage of the GhostAction campaign. After a phishing wave on 2026-10-09 stole GitHub OAuth tokens through a look-alike `my-github.com`, and GitHub began blocking the malicious workflow, the operator committed three files to 94 repositories of 66 owners: a `.vscode/tasks.json` with `runOn: folderOpen`, a stealer disguised as `public/fonts/fa-solid-400.woff2`, and a second CI workflow with a gist fallback. A developer who opens the repository in VS Code and trusts the workspace runs the stealer, which installs a cron job every five minutes and sends data over plain HTTP on TCP/8080. The case matters today because a repository is executable content for whoever opens it, and because owners who removed stage 1 without revoking the stolen token received stage 2. There is no hash, no CVE and no confirmed actor.

## Attribution and confidence

| Field | Value |
|---|---|
| Cluster | Unattributed operator of the GhostAction supply chain campaign; no alias published |
| Vendors and dates | OpenSourceMalware 2026-10-19 (Paul McCarty, Jenn Gile); The Hacker News 2026-10-19; GitGuardian (Gaetan Ferry, Guillaume Valadon) for the wider campaign, reported by THN 2026-10-15 |
| Motivation | Credential theft: AWS keys, PyPI, npm, Git logins, Kubernetes, SSH keys and AI provider keys (Anthropic Claude, Google Gemini) |
| Confidence | **High** that stage 1 and stage 2 happened as reported (named by the researchers). **Low** for attribution: the sources only say the approach "takes a leaf out of North Korea's playbook" and that the file name matches an earlier Fake Font lure. **Low** for the link between the look-alike domains and the GhostAction operator named in earlier waves |

| Overlap | Relation |
|---|---|
| Fake Font / Contagious Interview (OpenSourceMalware, 2026-01-28) | Same trick, different file: `fa-brands-regular.woff2`, `tasks.json` with `folderOpen`, BeaverTail then InvisibleFerret; attributed there to North Korean actors. The name and technique overlap is not evidence of the same operator |
| npm and Go package hijacks (JFrog, THN, 2026-06-29/30) | Same folderOpen and fake font technique with blockchain dead drops and a socket.io backdoor; attributed to the Fake Font branch |
| GhostAction waves (GitGuardian, 2025-09 and 2026-08-31 to 2026-10-12) | Stage 1 workflow theft of CI secrets; stage 2 is the new persistence on developer machines |
| my-gitlab.com | Registered earlier in 2026; different registrar, nameservers, IP and ASN, so researchers find no confirmed link |

Genealogy in this repo: `2026-08-06_Keyv-Cacheable-npm-Worm-ShaiHulud-HereWeGoAgain` is the nearest case (autostart hooks in repositories). No earlier case covers GhostAction or the fake font technique. Anti-duplicate check: `grep -rliE 'ghostaction|PolinRider|fa-solid-400' days/ byActor/` before publishing found only that Shai-Hulud case.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Phishing email | T1566.002 | `noreply@my-github.com` imitates a GitHub alert about a login from Moscow, 2026-10-09 |
| Reverse proxy | T1528 | Password and 2FA code captured through a proxy kit |
| OAuth device flow | T1528 | Injected JavaScript approves a device-flow grant with `repo`, `workflow`, `read:org`; token sent to my-github.com on TCP/8443 |
| Stage 1 workflow | T1552.001, T1041 | Workflow in `.github/workflows/` enumerates repositories and sends secrets to 193.32.204.199 |
| Stage 2 commit | T1195.001 | Three files committed: `tasks.json`, fake font, second workflow (8 reported names) |
| Developer opens repo | T1204.002, T1059.007, T1036.008 | Trusted workspace runs `node` on the fake font |
| Persistence and exfiltration | T1053.003, T1059.004, T1041 | Cron every five minutes; plain HTTP on TCP/8080; gist fallback for the workflow |
| Credential theft | T1552.001, T1552.004, T1567 | AWS, PyPI, npm, Git, Kubernetes, SSH keys and AI provider keys |

![GhostAction stage 2 kill chain](./kill_chain.svg)

The left lane follows the attack from the phishing email to the stolen secrets; red stages are the points where a defender's control matters most: the OAuth grant, the planted files and the workspace trust prompt. The right lane records the indicators, the scope, the detection anchors and the source conflicts. Detection anchors are node running a `.woff2` file, a `tasks.json` with `folderOpen`, a crontab started from node, the two domains and the IP address.

## Stage-by-stage detail

### Stage 1: phishing and OAuth device flow

The email came from `noreply@my-github.com`, registered on 2026-10-09, the same day GitHub began blocking the malicious workflow. A reverse proxy collected the password and the 2FA code. Injected JavaScript then loaded GitHub's `/login/device`, inserted the user code, added `authorize=1` and posted the approval, so the victim never saw a consent screen. The token had `repo`, `workflow` and `read:org` scopes and was sent to my-github.com on TCP/8443. Techniques: T1566.002 and T1528.

### Stage 2: the planted workflow

A malicious workflow in `.github/workflows/` enumerated repositories and sent secrets to 193.32.204.199. GitHub blocked it from 2026-10-09; the waves of 2026-10-10 and 2026-10-12 extracted no secrets (GitGuardian). Names reported for the wider campaign include `security-audit.yml` and `github_actions_security.yml`. Techniques: T1552.001 and T1041.

### Stage 3: stage 2 files committed to 94 repositories

About six days after the block (inferred, around 2026-10-15) the operator committed three files to 94 repositories of 66 owners; 15 have since been deleted, renamed or made private, 79 remain accessible and 65 of those 79 have had no commits for over a year (one for more than nine years).

```text
.vscode/tasks.json            runOn: folderOpen, runs node on the fake font
public/fonts/fa-solid-400.woff2   JavaScript stealer, not a font
.github/workflows/<lint|ci-check|build-check|repo-health|audit|code-review|test-suite|cache-cleanup>.yml
                              second workflow, more credential patterns, secret gist fallback
```

Technique: T1195.001.

### Stage 4: the developer opens the repository

When a developer opens the folder in VS Code (or a fork such as Cursor) and trusts the workspace, the task runs `node` on the fake font. The January 2026 Fake Font lure used the same pattern with `"command": "node"` and the font path as argument and `"reveal": "never"` to hide the terminal. The payload is JavaScript starting with a try/catch and no line breaks in that lure; the stage 2 file of this case has not been published. Techniques: T1204.002, T1059.007, T1036.008.

### Stage 5: persistence and exfiltration

The stealer installs a cron job that runs attacker-supplied code every five minutes and sends data over plain HTTP on TCP/8080 to what the report calls the same server; the report does not name its address. The report does not say whether the body is encrypted by the stealer itself. Techniques: T1053.003, T1059.004 and T1041.

### Stage 6: credentials targeted

AWS keys, PyPI tokens, npm tokens, Git logins, Kubernetes cluster credentials, SSH private keys and AI provider credentials (Anthropic Claude and Google Gemini). If the POST fails, the second workflow uploads findings to a secret GitHub gist. Techniques: T1552.001, T1552.004 and T1567.

## Detection strategy

There is no sample hash, so detection rests on behaviour that the sources describe: a script interpreter reading a font file, an auto-run task in a cloned repository, a cron job created by a Node process, and the published domains and IP address. Network indicators are retrospective and may be dead.

### Telemetry that matters

- Process creation: Sysmon Event ID 1 and Defender `DeviceProcessEvents` for `node` with a `.woff2` argument and for `crontab` with a Node parent.
- File events: Sysmon Event ID 11 and `DeviceFileEvents` for `.vscode/tasks.json` written by `git` and for new files under `.github/workflows/`.
- Network and DNS: Sysmon Event ID 3 and 22, `DeviceNetworkEvents`, proxy logs, Suricata DNS, TLS and HTTP metadata.
- GitHub: organisation audit log (OAuth authorisations, workflow runs), account security log, secret gist list.
- Linux: `crontab -l`, `/var/spool/cron/`, auditd on `crontab`.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [sigma/01_node_executes_woff2_file_fake_font_loader.yml](./sigma/01_node_executes_woff2_file_fake_font_loader.yml) | Windows: node.exe with a .woff2 argument |
| Sigma | [sigma/02_linux_node_executes_woff2_file_fake_font_loader.yml](./sigma/02_linux_node_executes_woff2_file_fake_font_loader.yml) | Linux and macOS: node with a .woff2 argument |
| Sigma | [sigma/03_node_spawns_crontab_persistence.yml](./sigma/03_node_spawns_crontab_persistence.yml) | crontab started by a node process |
| Sigma | [sigma/04_dns_query_my_github_my_gitlab_lookalike_domains.yml](./sigma/04_dns_query_my_github_my_gitlab_lookalike_domains.yml) | DNS query for the two look-alike domains |
| Sigma | [sigma/05_workflow_file_created_with_ghostaction_stage2_names.yml](./sigma/05_workflow_file_created_with_ghostaction_stage2_names.yml) | Workflow file with one of the ten reported names |
| KQL | [kql/k1_node_executing_woff2_file.kql](./kql/k1_node_executing_woff2_file.kql) | node running a .woff2 file in the last 30 days |
| KQL | [kql/k2_vscode_tasks_json_written_by_git.kql](./kql/k2_vscode_tasks_json_written_by_git.kql) | tasks.json written by git, then node from the editor within 10 minutes |
| KQL | [kql/k3_connections_to_ghostaction_infrastructure.kql](./kql/k3_connections_to_ghostaction_infrastructure.kql) | Connections to the two domains and the IP address |
| YARA | [yara/ghostaction_fake_font_and_folderopen_task.yar](./yara/ghostaction_fake_font_and_folderopen_task.yar) | Two rules: a non-WOFF2 file with JavaScript tokens; a tasks.json that runs node on a .woff2 path |
| Suricata | [suricata/ghostaction_stage1_stage2_network.rules](./suricata/ghostaction_stage1_stage2_network.rules) | Seven rules, sids 6380001 to 6380007: DNS, SNI, IP, TCP/8443, POST on 8080, HTTP Host |

The YARA rules were not run against a real sample because none is public. The 8080 Suricata rule is a hunt lead with low confidence, since any plain HTTP POST on that port matches.

### Threat hunting hypotheses

- **H1.** A repository cloned by a developer contains a `tasks.json` with `runOn: folderOpen` that runs code: [hunts/peak_h1_vscode_folderopen_tasks_in_cloned_repositories.md](./hunts/peak_h1_vscode_folderopen_tasks_in_cloned_repositories.md).
- **H2.** A file named as a font is not a font: [hunts/peak_h2_fake_font_files_that_are_not_woff2.md](./hunts/peak_h2_fake_font_files_that_are_not_woff2.md).
- **H3.** An account or secret was exposed after an affected repository was opened or a malicious OAuth grant was created: [hunts/peak_h3_token_and_secret_exposure_after_opening_an_affected_repository.md](./hunts/peak_h3_token_and_secret_exposure_after_opening_an_affected_repository.md).

## Incident response playbook

### First 60 minutes (triage)

1. Identify which repositories and developers are in scope: your organisation's repositories with `public/fonts/fa-solid-400.woff2` or a `tasks.json` with `folderOpen`, and every clone of them (hunts H1 and H2).
2. From a clean device, revoke the affected users' OAuth grants and personal access tokens and sign out all GitHub sessions; do this before cleaning the repository.
3. Isolate any workstation where `node` read a `.woff2` file or where a new cron entry exists; keep it powered on for memory collection if policy allows.
4. List cron entries and recently created workflows (commands below) and preserve a copy of the fake font, the `tasks.json` and the workflow files before removing anything.
5. Inventory every secret reachable from the affected workflows and the affected machines; start rotation with cloud keys and package registry tokens.
6. Check cloud and registry logs for use of those secrets after 2026-10-09.
7. Block my-github.com, my-gitlab.com and 193.32.204.199 at DNS and proxy, understanding they may already be dead.
8. Tell the developers who cloned the repositories, and ask whether anyone opened a repository from a recruiter or an unfamiliar source.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Fake font file | `<repo>/public/fonts/fa-solid-400.woff2` | cp, sha256sum | Sample for analysis; first hash for this campaign |
| Task file | `<repo>/.vscode/tasks.json` | cp | Command and trigger |
| Workflow files | `<repo>/.github/workflows/*.yml` | git log, cp | Secret patterns and exfiltration target |
| Crontab | `crontab -l`, `/var/spool/cron/` | crontab, ls | Persistence line and its content |
| Node history | `~/.npm/`, shell history, temp directories | ls, find | Dropped files and stages |
| VS Code state | `Code/User/globalStorage/state.vscdb`, workspace trust records | sqlite3 | When the workspace was trusted |
| GitHub logs | Audit log, account security log | gh api | OAuth grants, workflow runs, gists |
| Network logs | Proxy, DNS, Suricata, EDR | KQL, zeek-cut | Contact with the domains, IP address and ports 8443 and 8080 |

### IR queries and commands

```bash
# Author: Jarmi
# Find .woff2 files in cloned repositories that do not start with the WOFF2 magic bytes, and tasks.json files with folderOpen.
find "$HOME" -type f -name '*.woff2' -not -path '*/node_modules/*' 2>/dev/null | while read -r f; do [ "$(head -c4 "$f")" = "wOF2" ] || echo "NOT-WOFF2 $f"; done
find "$HOME" -path '*/.vscode/tasks.json' 2>/dev/null | xargs grep -l 'folderOpen' 2>/dev/null
```

```bash
# Author: Jarmi
# Show the current user's crontab and any system cron entries changed in the last 14 days (read-only).
crontab -l 2>/dev/null; sudo find /etc/cron* /var/spool/cron* -type f -mtime -14 -ls 2>/dev/null
```

```powershell
# Author: Jarmi
# Windows: list node processes whose command line contains .woff2, and tasks.json files with folderOpen in the user profile.
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*.woff2*' } | Select-Object ProcessId, CommandLine
Get-ChildItem $env:USERPROFILE -Recurse -Filter tasks.json -ErrorAction SilentlyContinue | Select-String 'folderOpen' | Select-Object Path
```

```kql
// Author: Jarmi
// Defender XDR: devices that ran node on a .woff2 file or contacted the published indicators in the last 30 days.
union
 (DeviceProcessEvents | where Timestamp > ago(30d) and FileName in~ ("node.exe","node") and ProcessCommandLine has ".woff2" | project Timestamp, DeviceName, Detail = ProcessCommandLine),
 (DeviceNetworkEvents | where Timestamp > ago(30d) and (RemoteIP == "193.32.204.199" or RemoteUrl has_any ("my-github.com","my-gitlab.com")) | project Timestamp, DeviceName, Detail = strcat(RemoteIP, " ", RemoteUrl))
| sort by Timestamp desc
```

### Containment, eradication, recovery

Exit criteria: all OAuth grants and tokens of affected accounts revoked and re-issued from a clean device; the fake font, the `tasks.json` and the planted workflows removed from every branch and from open pull requests; no unexpected cron entries or node-created files on any workstation; every reachable secret rotated and its use after 2026-10-09 reviewed; endpoints that ran the payload re-imaged or verified by a full triage.

What not to do: do not delete the files from the repository and stop there, because owners who removed stage 1 without revoking the token received stage 2; do not run or open the fake font on a normal workstation; do not tell developers to simply decline the trust prompt as the only control; do not present the published indicators as live without re-validating them.

### Recovery validation

- Re-run hunts H1 and H2 on all clones and repositories, then again after 14 days.
- Confirm in the GitHub audit log that no new OAuth grant, workflow or secret gist appears for the affected accounts.
- Confirm that no secret from the rotation list is used from an unfamiliar address.

## IOCs

All indicators are retrospective and may be offline. The stage 2 file has no published hash. Three rows in `iocs.csv` (a domain and two IP addresses) belong to related campaigns and are labelled as such. Full list in [iocs.csv](./iocs.csv).

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| domain | my-github.com | Phishing, OAuth proxy, token exfiltration; registered 2026-10-09 | medium | THN / OpenSourceMalware |
| domain | my-gitlab.com | Naming pivot; no confirmed link | low | THN / OpenSourceMalware |
| ipv4 | 193.32.204.199 | my-github.com resolved here; stage 1 exfiltration | medium | THN / OpenSourceMalware |
| email | noreply@my-github.com | Phishing sender | medium | THN / OpenSourceMalware |
| path | public/fonts/fa-solid-400.woff2 | Stage 2 stealer disguised as a font | medium | THN / OpenSourceMalware |
| path | .vscode/tasks.json | Launcher with folderOpen | medium | THN / OpenSourceMalware |
| string | "runOn": "folderOpen" | Auto-run trigger | medium | THN, OpenSourceMalware |
| path | .github/workflows/lint.yml and seven other names | Second workflow names (generic) | low | THN / OpenSourceMalware |
| path | .github/workflows/security-audit.yml, github_actions_security.yml | Stage 1 names for the wider campaign | medium | THN / GitGuardian |
| note | TCP/8443 and TCP/8080 | Ports as reported; host mapping unclear | medium | THN |
| note | 94 repositories, 66 owners, 79 accessible | Scope as reported | medium | THN |
| domain | eth-mainnet-alchemy.com | Related Fake Font C2 (January 2026), not GhostAction | low | OpenSourceMalware |
| ipv4 | 166.88.134.62 | Related June 2026 package hijack backdoor, not GhostAction | low | JFrog via WebProNews |
| ipv4 | 198.105.127.210 | Related June 2026 package hijack backdoor, not GhostAction | low | JFrog via WebProNews |

KEV: not applicable. No CVE is named in any source; the attack abuses stolen tokens, repository content and VS Code workspace trust, so `kev.md` is not generated for this case.

## Secondary findings

- **SlugFest, npm trusted publishing (Bloom Security, reported to GitHub 2026-06-06; GitHub change dated 2026-10-02).** npm tied a package to a GitHub repository by the name `owner/repository`, not by its numeric ID, until the first successful publish, so a freed name could be claimed and give publish rights without stealing a credential. More than 1,500 packages (over 10 million downloads) were exposed. GitHub now expires unvalidated bindings after 48 hours and rejects trusted publishing tokens from `issue_comment` events. Action: audit trusted publisher bindings and recreate any that point to a renamed, transferred or deleted repository.
- **Repeat victims of earlier GhostAction waves (GitGuardian).** Some of the October 8 to 9 victims were also hit in September 2025 and August 2026, which points to secrets that were never rotated. Roughly 1,900 accounts were compromised and about 28,000 new repositories were targeted within 20 minutes of the spike; the payload gained git-history scanning and AWS key-pair pairing across three versions.
- **Fake Font in packages (JFrog, Nextron Systems, 2026-06).** The same folderOpen and font trick appeared in npm packages `html-to-gutenberg 4.2.11` and `fetch-page-assets 1.2.9` and in 16 Go modules, with TronGrid, Aptos and BSC dead drops and a socket.io backdoor.

## Pedagogical anchors

- A repository is executable content for whoever opens it. VS Code workspace trust and `task.allowAutomaticTasks` are security controls; keep untrusted code in Restricted Mode and treat recruiter test projects as hostile.
- Judge a file by its header, not its extension. A real WOFF2 starts with `wOF2`; anything else with that name is a disguised script.
- Order of cleanup matters: revoke the stolen token first, then clean the repository, or the attacker simply re-infects.
- Behaviour beats names. Generic file names (`lint.yml`, `audit.yml`) cannot be blocked, but node reading a font or creating a cron job can be detected.
- Retrospective indicators decay. Write down what is unknown (no hash, no actor, unclear port mapping) instead of filling the gap.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram (Template A). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | 24 rows: domains, IP address, e-mail, file and workflow paths, related-campaign indicators and notes. | [iocs.csv](./iocs.csv) |
| sigma/ | Five Sigma rules for node on a font file, crontab from node, look-alike domains and workflow names. | [sigma/](./sigma/) |
| kql/ | Three KQL queries for node on fonts, tasks.json then node, and infrastructure contact. | [kql/](./kql/) |
| yara/ghostaction_fake_font_and_folderopen_task.yar | Two YARA rules for the fake font and the folderOpen task (no sample exists). | [yara/ghostaction_fake_font_and_folderopen_task.yar](./yara/ghostaction_fake_font_and_folderopen_task.yar) |
| suricata/ghostaction_stage1_stage2_network.rules | Seven Suricata rules, sids 6380001 to 6380007. | [suricata/ghostaction_stage1_stage2_network.rules](./suricata/ghostaction_stage1_stage2_network.rules) |
| hunts/ | Three PEAK hunts (H1 to H3). | [hunts/](./hunts/) |

## Sources

- [GhostAction attackers plant credential stealers in fake font files — The Hacker News, 2026-10-19](https://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html)
- [GhostAction compromises about 1,900 accounts — The Hacker News, 2026-10-15 (GitGuardian)](https://thehackernews.com/2026/10/ghostaction-compromises-about-1900.html)
- [Fake Font campaign: DPRK Contagious Interview uses malicious VS Code fonts — OpenSourceMalware, 2026-01-28](https://opensourcemalware.com/blog/dprk-contagious-interview-campaign-fake-font-uses-malicious-vs-code-fonts)
- [VS Code Tasks Become Silent Killers in Fresh npm and Go Package Hijacks — WebProNews, 2026-06-30 (JFrog, Nextron)](https://www.webpronews.com/vs-code-tasks-become-silent-killers-in-fresh-npm-and-go-package-hijacks/)
- [GitHub tightens npm publishing after SlugFest — The Hacker News, 2026-10-13 (Bloom Security)](https://thehackernews.com/2026/10/github-tightens-npm-publishing-after.html)

The sources were read through automated page summaries, not in a browser. Unresolved: the primary OpenSourceMalware report on stage 2 was not retrieved, so the stage 2 details come from The Hacker News; the stage 2 server address, the cron line, the payload hash and the port mapping (8443 for tokens, 8080 for the stealer) are not published; the first GhostAction attribution in earlier waves is not stated by GitGuardian.
