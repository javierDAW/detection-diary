# PEAK H2 — Showboat user-space process masquerading as kworker on Linux

**Date:** 2026-05-22
**Author:** Jarmi
**Hypothesis class:** Hypothesis-driven (PEAK)
**Confidence:** high

## Hypothesis

A Linux host in our estate runs a user-space process whose name starts with
`kworker` that performs outbound TCP connections on port 80, 443, 53, 2096 or
9999, or fetches a snippet from `pastebin.com` or a similar paste site for
use as a dead-drop. Real `kworker` threads are kernel-space and never appear
in user-process telemetry — any match is the Showboat / Red Lamassu
implant masquerading after the hide command was issued.

## Why this discriminates

- The kernel emits `kworker/N:H` threads for per-CPU async work — these have
  no PID with `proc/<pid>/exe` and never invoke `connect()` from user space.
- Showboat copies the kworker name into its own argv to blend in. EDRs that
  hook `execve` will report the binary by its actual `exe` path, not by the
  fake argv[0].
- The hide command pulls operator-controlled code from Pastebin or an online
  forum and `eval`s it as a dead-drop — egress from a process named kworker
  to one of those domains is impossible benign.

## Expected benign vs malicious

- Benign: zero — no legitimate workflow names a user process `kworker` and
  has it talk to Pastebin or the seven Red Lamassu C2 anchors.
- Malicious: a process whose `comm` is `kworker` but whose `exe` resolves to
  `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/home/<user>/.cache/`, or any non-kernel
  path, performing outbound TLS to one of the published Showboat C2 domains
  on port 2096 (Cloudflare TLS) or 9999 (SOCKS5 banner).

## Action on match

1. Capture a memory image of the host with AVML or LiME before touching disk.
2. Collect `/proc/<pid>/exe`, `/proc/<pid>/maps`, `/proc/<pid>/environ` and
   the open file descriptors for the suspect process.
3. YARA-scan all ELF files under `/tmp`, `/var/tmp`, `/dev/shm`, `/home` and
   `/root` for the Showboat heuristic anchor (`look me, AV!` XOR taunt and
   `kworker` + `SKS`/`MAP` markers).
4. Hunt netflow for connections to the published Red Lamassu IP set
   (139.84.227.139, 194.135.25.132, 64.176.43.209, 192.9.141.111,
   116.169.244.208) back to 2022-07-01.
5. Treat any Outlook server, edge router or load-balancer with this anchor
   as a pivoting point — Showboat is a SOCKS5 foothold designed to reach
   internal LAN devices.

## Linked rules

- `sigma/showboat_kworker_pastebin_deaddrop.yml`
- `kql/showboat_kworker_anomalous_egress.kql`
- `kql/red_lamassu_c2_egress_telecom_themed_domains.kql`
- `yara/RedLamassu_JFMBackdoor_Showboat_2026.yar`
- `suricata/red_lamassu_2026_05.rules` (sids 8220003, 8220004, 8220007, 8220008)
