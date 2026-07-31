# PEAK Hunt H2 - Fileless Miner: Deleted Executable + /tmp/.lock

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If the V25 XMRig runs memory-resident, then a live host shows a process whose `/proc/<pid>/exe` points at a `(deleted)` path while `/tmp/.lock` exists, with CPU pinned and Huge Pages allocated.

## Prepare

- **ATT&CK:** T1070.004 (Indicator Removal: File Deletion), T1564.013 (Hide Artifacts), T1496 (Resource Hijacking).
- **Data sources:** live `/proc`, auditd `file_event`/`unlink`, EDR process telemetry, host CPU metrics.
- **Scope:** any Linux host; prioritize those flagged by H1 or with unexplained sustained CPU.

## Execute

```bash
# Processes running from a deleted on-disk backing file
ls -l /proc/*/exe 2>/dev/null | grep -F '(deleted)'

# Presence of the single-instance mutex
[ -e /tmp/.lock ] && stat /tmp/.lock

# High-CPU processes with masqueraded names (e.g. comm=ssh but odd exe path)
ps -eo pid,comm,%cpu,etime --sort=-%cpu | head
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$p/exe 2>/dev/null)
  [ -n "$exe" ] && echo "$p $(cat /proc/$p/comm 2>/dev/null) -> $exe"
done | grep -iE 'deleted|ssh'

# Huge Pages allocated (miner optimization)
grep -E 'HugePages_(Total|Free)' /proc/meminfo
```

## Act with Knowledge

- **Confirmed malicious:** a `(deleted)`-backed process pinning CPU alongside `/tmp/.lock`. Do NOT reboot - acquire memory first (AVML/LiME) and carve the XOR config (pool host, `My-V25-GEN-26`).
- **Benign baseline:** some apps run briefly from deleted temp files during upgrades; the miner is persistent and CPU-bound - use duration + CPU to separate.
- **Feed forward:** recovered pool host / markers feed H3 and the IOC feed; the owning account feeds the cron sweep.
