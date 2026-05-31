# PEAK H1 — Imposter-commit secret theft on GitHub Actions runners

**Date:** 2026-05-21
**Author:** Jarmi
**Hypothesis class:** Hypothesis-driven (PEAK)
**Confidence:** high

## Hypothesis

A GitHub Actions workflow in our org has executed `actions-cool/issues-helper`
or `actions-cool/maintain-one-comment` referenced by a floating tag (`@v3`,
`@v3.8.0`, ...) between 2026-05-18T19:10:24Z and now. If yes, the runner
that executed the job pulled the TeamPCP imposter commit, downloaded the
`bun` runtime, spawned a `sudo python3` child that read
`/proc/<Runner.Worker PID>/mem`, scraped decrypted CI/CD secrets and
exfiltrated to `t.m-kosche.com/api/public/version`.

## Why this discriminates

- The imposter commit's `dist/index.js` calls `bun.sh/install` and then
  `~/.bun/bin/bun -e "$(curl -fsSL ...)"` — bun is not a default tool on
  GitHub-hosted runners and would never appear in legitimate Node.js
  action runtimes.
- The `python3` child opening `/proc/<other PID>/mem` is the
  highest-confidence anchor — no legitimate GitHub Action reads another
  process's memory.
- The exfil domain `t.m-kosche.com` has no known legitimate use; any
  egress is the smoking gun.

## Expected benign vs malicious

| Observation | Benign | Malicious |
|---|---|---|
| `actions-cool/issues-helper@v3` reference | Common before 2026-05-18 | All references resolved post-2026-05-18T19:10:24Z |
| `bun` install on a runner | Possible for legitimate JS tooling | Combined with `python3` /proc/mem read = compromise |
| Egress to `t.m-kosche.com` | None | Always malicious |

## Data sources

- GitHub Actions audit log (`gh run list`, `gh run view`).
- Self-hosted runner host telemetry: auditd `execve`, Sysmon for Linux EID
  1 + 3.
- Egress sensor in front of the runner subnet (zeek, Suricata, or cloud
  flow logs).
- StepSecurity Harden-Runner Insights — direct first-party telemetry.

## Hunt queries

### KQL — Defender XDR (self-hosted Linux runner with MDE)

```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName == "python3" or FileName == "python"
| where ProcessCommandLine has_all (dynamic(["/proc/","/mem"]))
       or ProcessCommandLine has_any (dynamic(["isSecret","gh auth token","/home/runner/.bun/bin/bun","Runner.Worker"]))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Bash — runner sweep

```bash
# Search workflow files for actions-cool references not pinned to a clean SHA
grep -RnE 'actions-cool/(issues-helper|maintain-one-comment)@(v[0-9]+|main|master|[0-9a-f]{1,39}\b)' \
    .github/workflows/
```

```bash
# Search runner audit logs for bun + python3/proc/mem pattern
ausearch -ts recent -m EXECVE | \
  awk '/python3/ && /proc/ && /mem/' | head
```

## Action on match

1. Quarantine the runner host at host firewall level.
2. Collect RAM dump and `/tmp` snapshot.
3. Identify all secrets the workflow had access to (`GITHUB_TOKEN`, OIDC,
   cloud creds, registry tokens).
4. Revoke and rotate, in this strict order: AWS IAM keys → Azure SP
   secrets → GCP SA keys → npm/PyPI tokens → GitHub PATs → SSH keys.
5. Repin every reference to a known-good SHA pre-2026-05-18T19:10Z.
6. Open IR ticket referencing this hunt and the kill-chain SVG.
