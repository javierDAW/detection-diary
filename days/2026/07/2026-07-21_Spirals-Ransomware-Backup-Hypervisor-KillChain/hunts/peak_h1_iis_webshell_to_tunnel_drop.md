# PEAK Hunt H1: IIS Web Shell to Tunnel-Tool Drop

**Author:** Jarmi
**Date:** 2026-07-21
**Case:** Spirals ransomware
**Hypothesis type:** Domain-based hunt (initial access + staging)

## Hypothesis

*If* an internet-facing IIS server is compromised via a web shell, *then*
within a short window (Symantec observed under 10 minutes) the worker
process will spawn an interactive shell and drop one or more
tunneling/proxy binaries into predictable staging locations (web production
directories, the Windows Tasks folder) to establish covert outbound
connectivity before any further lateral movement begins.

## Why this matters

Spirals compromised its victim's IIS server and had three redundant tunnels
(revsocks, Chisel-as-chrome.exe, Cloudflare Tunnel) running within 10
minutes of the first web shell command. This narrow window is the earliest
point at which the intrusion is both fully attributable to the entry vector
and still confined to a single host — the highest-leverage moment to
interrupt the chain.

## Data sources

- Sysmon Event ID 1 (process creation) for all IIS worker processes
  (`w3wp.exe`) across internet-facing web tiers
- Sysmon Event ID 11 (file create) for `.exe` writes under IIS web roots,
  `%PUBLIC%`, and `%WINDIR%\Tasks`
- Sysmon Event ID 3 (network connection) for new outbound TCP/443 sessions
  initiated by `w3wp.exe` or a process it spawned

## Procedure

1. Enumerate every internet-facing IIS host in the environment (asset
   inventory or exposure-management tooling).
2. For each host, pull Sysmon EID 1 events where `ParentImage` ends with
   `w3wp.exe` for the trailing 30 days.
3. For any hit, pivot to EID 11 file-create events on the same host within
   +/- 15 minutes of the shell spawn, filtering to `.exe` extensions outside
   normal IIS deployment paths.
4. For any file-create hit, pivot to EID 3 outbound network connections from
   the newly created binary within the following 5 minutes.
5. Escalate any host showing all three stages (shell spawn -> unexpected
   .exe drop -> new outbound connection) as a confirmed or probable web
   shell-to-tunnel chain, matching the Spirals `sigma/spirals_iis_webshell_process_spawn.yml`
   rule logic.

## Expected legitimate activity (false positives)

Deployment automation or health-check scripts that intentionally shell out
from the worker process; these should be inventoried once and excluded by
AppPool identity or parent command line rather than by suppressing the hunt
entirely.

## Related detections

`sigma/spirals_iis_webshell_process_spawn.yml`
