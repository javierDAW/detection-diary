# PEAK H1 — QLNX credential-burst on developer / DevOps host

> Author: Jarmi · Date: 2026-05-07
> Reference: [Trend Micro — Quasar Linux (QLNX): A Silent Foothold in the Software Supply Chain (5-may-2026)](https://www.trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html)

## Hypothesis (PEAK Prepare → Execute → Act → Knowledge)

> A developer or DevOps endpoint in our fleet has been compromised by a QLNX-class implant. We will see a single non-developer process touch three or more **developer-credential files** (`.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, `.vault-token`, `~/.config/gh/hosts.yml`, `.netrc`, `.ssh/id_rsa`, `.ssh/id_ed25519`) within a 60-second window — followed by an outbound connection to `ip-api.com` (geo enrichment for the initial QLNX beacon).

## Why this is the right anchor

QLNX implements credential harvesting as a single C2 command (operator triggers it from the panel). The harvester walks the user's home directory and reads every secret in one sweep — that is, in a tight time window. The first successful run is typically followed within minutes by an `ip-api.com` lookup that QLNX uses to populate the geolocation field of its first beacon. The two events together ("file-burst → geo-recon") are extremely uncommon in benign telemetry.

## Data sources

| Layer | Source | Required fields |
|---|---|---|
| File reads | Defender XDR `DeviceFileEvents` (Linux MDE) **or** auditd watch rules (`-w /home/*/.npmrc -p r -k qlnx_creds` etc.) **or** sysmon-for-linux `FileRead` | `Timestamp`, `DeviceName`, `InitiatingProcessId`, `InitiatingProcessFileName`, `FolderPath`, `FileName` |
| Network | Defender XDR `DeviceNetworkEvents` **or** Zeek `dns.log` + `conn.log` | `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName` |

## Execute

Run the KQL hunts in this folder (24h scope, then expand to 7d if dirty):

1. [`qlnx_credential_files_burst.kql`](../kql/qlnx_credential_files_burst.kql) — burst of credential reads.
2. [`qlnx_ipapi_geo_beacon.kql`](../kql/qlnx_ipapi_geo_beacon.kql) — geolocation recon.
3. [`qlnx_ld_preload_modification.kql`](../kql/qlnx_ld_preload_modification.kql) — confirm persistence.

Correlate by `DeviceName`. Any host that triggers (1) AND (2) within ±10 minutes is a high-confidence finding regardless of (3).

## Triage tree

```
Burst hit?
├── Yes  → Did we ALSO see ip-api.com from the same DeviceName within ±10 min?
│         ├── Yes → Critical. Pivot to /etc/ld.so.preload diff (qlnx_ld_preload_modification),
│         │        capture /proc/<pid>/exe before kill, snapshot home dirs, isolate.
│         └── No  → Suspicious. Walk the parent process tree; was the burst initiated
│                   by a CI/CD script, by a developer's editor, or by an unknown ELF
│                   under /tmp /var/tmp /dev/shm?  Pivot to QLNX_MANAGED grep.
└── No   → Negative for this hunt window. Re-baseline weekly; this hunt is cheap to
           run continuously.
```

## What good vs. evil looks like

**Benign**
- A developer logs in, runs `gh auth status`, then `aws sts get-caller-identity`, then `kubectl config current-context` — three credential reads but each by a *different, named tool* and over minutes, not seconds.
- A CI/CD agent (Jenkins/Buildkite) reads `.npmrc` and `.git-credentials` but executes from a known build path; allowlist by parent and binary path.

**Evil**
- A single `bash`/`tar`/`find`/`python3` process reads `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials` and `.kube/config` in 12 seconds — and was spawned by an ELF under `/tmp/.X752e2ca1-lock` or `/var/log/.ICE-unix`.
- The parent of that burst is `pid 1` (systemd) but the binary path is missing or unsigned; QLNX runs in-memory and can null its `/proc/<pid>/exe`.

## Knowledge (what we feed back)

If positive:

1. Pin the binary's structural fingerprint in the [`yara/QLNX_Quasar_Linux_RAT_2026.yar`](../yara/QLNX_Quasar_Linux_RAT_2026.yar) rule and re-scan disk fleet-wide.
2. Add the C2 endpoint to the org's egress denylist and to Suricata `qlnx_ipapi_recon.rules`.
3. Rotate every credential touched during the burst window: npm token, PyPI token, git PAT, AWS access keys, kube-config certs, Docker registry creds, Vault token, GitHub PAT, SSH keys.
4. Run `pkg verify` (rpm `-V`) / `debsums -c` against system PAM modules; recompare `/etc/pam.d/*` against last-known-good.
5. Re-image rather than clean — QLNX has seven persistence anchors and the LD_PRELOAD layer respawns on the next process exec.
