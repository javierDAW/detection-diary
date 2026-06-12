# PEAK Hunt H2 — ld.so.preload hiding library and listening-port discrepancy

**Hypothesis.** A userspace hiding library is installed via `/etc/ld.so.preload`
(LinkPro `libld.so` fallback, or Symbiote-class) and conceals a listening backdoor port
(LinkPro: TCP 2233) by forging `/proc/net/tcp*` reads. The port is therefore invisible to
`netstat` (which reads `/proc/net`) but visible to `ss` (which uses netlink) — a classic
hiding-tool seam.

**Why it works.** `libld.so` hooks `fopen/open` and strips any `/proc/net/tcp*` line whose
source/dest port matches the backdoor port, and hooks `getdents/readdir` to drop the
preload file, the backdoor file (`.tmp~data`), `sshids` and the `.system` directory from
directory listings. But it does not intercept the netlink path, so `ss` still shows the port.

## Data sources
- `/etc/ld.so.preload` content and `/etc/libld.so` presence (EDR file telemetry or live `stat`).
- Paired `netstat -tlnp` vs `ss -tlnp` output per host.
- `DeviceFileEvents` for the artifact names (see KQL).

## Analytic steps
1. Sweep `/etc/ld.so.preload`: any host where it exists AND references a path outside your
   sanctioned AV/observability allow-list is a lead.
2. On every host, diff listening ports from `ss -tlnp` against `netstat -tlnp`. A port that
   appears in `ss` but not `netstat` is a strong hiding-library indicator. LinkPro's port is
   2233, but the technique is port-agnostic — flag any discrepancy.
3. Stat the artifact names from a process that does NOT use glibc dynamic linking (e.g. a
   statically linked busybox or a Go binary you ship), because the preload hook only affects
   dynamically linked programs — a static tool sees the real directory.
4. Confirm by reading `/etc/ld.so.preload` with a static-binary `cat`; the hook returns
   "No Such File Or Directory" to glibc-linked tools but the static read succeeds.

## Expected benign
Hosts with a legitimate global preload (rare). Baseline and exclude.

## Pivots / escalation
Confirmed preload hiding → image the host, recover `/etc/libld.so` for YARA
(`MAL_LinkPro_LdPreload_libld`), and pivot to H1 (eBPF) and H3 (knock). Removing the
preload line without imaging destroys evidence; collect first.

Linked detections: `sigma/linux_ldso_preload_rootkit_persistence.yml`,
`kql/linkpro_ldpreload_and_hidden_artifacts.kql`.
