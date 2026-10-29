# PEAK hunt H1 - did any host, runner or image install the poisoned litellm 1.107.0?

## Prepare

**Hypothesis.** If any developer machine, CI runner, notebook or container ran `pip install litellm` (unpinned, or pinned to 1.107.0) between 2026-10-21 11:39 UTC and the PyPI quarantine at 13:23 UTC, or pulled the `latest`, `main-latest`, `main-stable` or `v1.107.0` image tags before they were pulled, then `cook.pth`, `cook.py` and `sitecustomize.py` sit in a `site-packages` root and the stealer ran at the next interpreter start.

**Why first.** It answers the exposure question that decides everything else (rotate or not). Wiz counts about 49,000 downloads in under two hours, and the payload does not need `import litellm`.

**Scope.** Endpoint file telemetry for 30 days, lockfiles and build logs in repositories, container image digests in registries and running clusters. Record the oldest telemetry date; a gap before 2026-10-21 means the answer covers only part of the window.

## Execute

```kql
// Author: Jarmi
// Defender XDR: startup-hook files by name or hash (full query in kql/k1).
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "site-packages" and FileName in~ ("cook.pth","cook.py")) or SHA256 in ("7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb","9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessCommandLine
```

```bash
# Author: Jarmi
# Repository and image sweep from a clean machine (never run python or pip inside the suspect environment).
grep -rnE 'litellm(==|>=|~=)?1\.107\.0' --include='requirements*.txt' --include='poetry.lock' --include='uv.lock' --include='Pipfile.lock' .
find / -path '*/site-packages/cook.pth' -o -path '*/site-packages/cook.py' 2>/dev/null
ls -la /tmp/.pc_once_* /tmp/remote_code_loader.lock 2>/dev/null
docker images --digests | grep -E 'litellm' ; kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.spec.containers[*].image}{"\n"}{end}' | grep -i litellm
```

## Act on

- Any `cook.pth` / `cook.py` hit or a matching image digest: treat the host as compromised, isolate it, rebuild from verified artifacts and rotate every credential it could reach (H3 shows what was used).
- Install intent without the files (pip command seen, wheel never served): record it, pin to 1.106.2 by digest and move on.
- Only `sitecustomize.py` without `cook.pth`: compare its SHA-256 with the IOC list before acting; legitimate files exist.

## Knowledge

Removing the package does not remove the stealer or the secrets it already took. The tampered `pyproject.toml` (`data = "cook"`) and Dockerfiles (`COPY cook ./cook`) explain why wheels and images, but not the sdist payload, were affected.
