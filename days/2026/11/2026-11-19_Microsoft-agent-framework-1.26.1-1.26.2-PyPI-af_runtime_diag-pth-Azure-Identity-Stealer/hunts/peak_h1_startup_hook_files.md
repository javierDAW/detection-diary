# PEAK hunt H1 - did any host, runner or image install agent-framework 1.26.1 or 1.26.2?

## Prepare

**Hypothesis.** If any developer machine, notebook, CI runner or container build resolved `agent-framework` to 1.26.1 or 1.26.2 between 2026-11-17 20:35 UTC (first malicious upload) and about 21:20 UTC (removal), then `agent_framework_meta.pth` (1.26.1) or `af_runtime_diag.pth` + `af_runtime_diag.py` (1.26.2) sit in a `site-packages` root and the collector ran at the next Python interpreter launch, even if `agent_framework` was never imported.

**ATT&CK.** T1195.001 (Compromise Software Dependencies and Development Tools), T1546.018 (Python Startup Hooks), T1059.006 (Python).

**Data sources.** Endpoint file events (Defender XDR `DeviceFileEvents`, Sysmon EID 11, auditd), process command lines (pip / uv / poetry), lockfiles and build logs in repositories, CI job logs, container image layers and registries, internal PyPI mirrors / proxies (Artifactory, Nexus, devpi) download logs.

**Scope window.** 2026-11-17 20:35 UTC onward. Installs after removal cannot fetch the malicious wheels from PyPI, but a mirror or cached wheel can still serve them; keep the window open-ended for caches and images built in the window.

## Execute

1. Query file telemetry for the three file names and the three published SHA-256 values (`kql/k1`, `sigma/01`).
2. Query process telemetry for pinned installs and for unpinned `agent-framework` installs inside the window (`kql/k2`, `sigma/02`).
3. Sweep repositories and build artifacts from a clean machine:

```bash
# Author: Jarmi
# Lockfiles and requirements that pin or resolved the malicious versions.
grep -rnE 'agent[-_]framework(==|@|-)?1\.26\.[12]\b' --include='requirements*.txt' --include='*.lock' --include='pyproject.toml' --include='Pipfile.lock' .
# Startup-hook files on a mounted image or host (do not start python in a suspect environment).
find / \( -path '*/site-packages/agent_framework_meta.pth' -o -path '*/site-packages/af_runtime_diag.pth' -o -path '*/site-packages/af_runtime_diag.py' \) 2>/dev/null
sha256sum $(find / -path '*/site-packages/af_runtime_diag.*' 2>/dev/null) 2>/dev/null
# Cached wheels in pip / uv caches and internal mirrors.
find ~/.cache/pip ~/.cache/uv / -name 'agent_framework-1.26.[12]-*.whl' 2>/dev/null
```

```powershell
# Author: Jarmi
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include agent_framework_meta.pth,af_runtime_diag.pth,af_runtime_diag.py |
  Where-Object { $_.FullName -match 'site-packages' } | Get-FileHash -Algorithm SHA256
```

4. Check internal PyPI proxy logs for downloads of `agent_framework-1.26.1-py3-none-any.whl` or `agent_framework-1.26.2-py3-none-any.whl`.

## Expected results

- Clean estate: no file hits, lockfiles pin 1.26.0 or a later clean release, proxy logs show no download of the two wheels.
- Exposed host: one or more startup-hook files with a creation time inside or shortly after the window, initiated by pip / uv / poetry.

## False positives

- Security researchers or this team reproducing the package in a lab.
- Lockfile lines that mention the versions only in exclusions (for example `!=1.26.1`).

## Action on match

- Startup-hook file present or wheel cached and installed: isolate the host or runner, preserve the files (hash them first), remove the package, rebuild from a verified image and rotate every credential reachable from that host (see H2 and H3).
- Install intent without files: record it, pin `agent-framework==1.26.0` (or a later clean version) with hashes and purge pip / uv caches.

## Knowledge

`pip uninstall` removes the files but not the secrets that were already sent. A `.pth` hook executes at interpreter start, so every Python process on an affected host (including unrelated tools) ran the collector.
