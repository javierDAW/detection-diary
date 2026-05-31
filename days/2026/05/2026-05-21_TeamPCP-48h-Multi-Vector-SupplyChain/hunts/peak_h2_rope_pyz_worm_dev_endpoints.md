# PEAK H2 — rope.pyz worm on CI/CD or developer hosts

**Date:** 2026-05-21
**Author:** Jarmi
**Hypothesis class:** Hypothesis-driven (PEAK)
**Confidence:** high

## Hypothesis

A developer or CI/CD host in our org installed `durabletask` v1.4.1,
v1.4.2 or v1.4.3 between 2026-05-19 (publish) and the host quarantine
moment. If yes, on first install or first `import durabletask`, the
malicious wheel injection point downloaded `rope.pyz`
(SHA256 `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`)
to `/tmp/managed.pyz` or `/tmp/rope-<random>.pyz`, executed with python3,
swept 90+ credential paths, dropped infection marker
`~/.cache/.sys-update-check` (or `~/.cache/.sys-update-check-k8s` if it
moved laterally) and attempted up to 5 AWS SSM and 5 Kubernetes lateral
hops per host.

## Why this discriminates

- The wheel hashes are first-party Wiz IoCs from 2026-05-19.
- `/tmp/managed.pyz` and `/tmp/rope-*.pyz` are unique artefact paths.
- `~/.cache/.sys-update-check` and `~/.cache/.sys-update-check-k8s` are
  unique infection markers — no legitimate use observed.
- Egress to `check.git-service.com` is exclusive to TeamPCP and has no
  legitimate consumers.

## Expected benign vs malicious

| Observation | Benign | Malicious |
|---|---|---|
| `pip install durabletask` | Common (Azure Durable Functions SDK) | Combined with `/tmp/*.pyz` drop within 5 min = compromise |
| `/tmp/*.pyz` artefact | Rare in production | Always investigate |
| `~/.cache/.sys-update-check` | Never legitimate | Confirms execution |
| `aws ssm send-command` from CI host | Possible in deployment pipelines | Combined with `/tmp/.rope_state/ssm_instances.json` = compromise |

## Data sources

- Linux MDE / Defender XDR: `DeviceProcessEvents`, `DeviceFileEvents`,
  `DeviceNetworkEvents`.
- auditd file create on `/tmp/*.pyz` and `~/.cache/.*`.
- AWS CloudTrail `ssm:SendCommand` and `ssm:DescribeInstanceInformation`
  from non-deployment subjects.
- Kubernetes audit log `pods/exec` from CI service accounts that have
  never `exec`-ed before.

## Hunt queries

### KQL — Defender XDR

See [`../kql/teampcp_durabletask_install_burst_then_pyz_drop.kql`](../kql/teampcp_durabletask_install_burst_then_pyz_drop.kql)
for the install-then-drop-then-exec join. Add this baseline scan to confirm
no latent execution:

```kql
let lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FolderPath has "/.cache/" and (FileName == ".sys-update-check" or FileName == ".sys-update-check-k8s")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

### Bash — host sweep

```bash
# Infection marker scan
sudo find / -type f \( -name '.sys-update-check' -o -name '.sys-update-check-k8s' \) 2>/dev/null

# Runtime artefacts
ls -la /tmp/managed.pyz /tmp/rope-*.pyz /tmp/.rope_state/ 2>/dev/null

# Lockfile and installed-package check
pip list 2>/dev/null | grep -i durabletask
grep -rE "durabletask[ \t]*==[ \t]*1\.4\.(1|2|3)" -- ./poetry.lock ./requirements*.txt ./pip-tools.lock 2>/dev/null
```

## Action on match

1. **Host quarantine BEFORE token revocation** — `rope.pyz` carries the
   Day-18 token-revoke destructive trigger; revoking tokens first triggers
   destructive payload.
2. RAM and `/tmp` capture.
3. Read `/tmp/.rope_state/ssm_instances.json` to enumerate which AWS
   instances the worm targeted. Repeat the scan on every targeted instance.
4. AWS CloudTrail review for `ssm:SendCommand` from compromised host
   credentials. Same for Kubernetes audit log `pods/exec`.
5. Rotate every secret in the host's credential scope.
6. Reimage. Do not "clean" — `rope.pyz` has filesystem + cron + LaunchAgent
   variants and we are not the operator.
