# PEAK Hunt H1 — Hidden eBPF programs (kernel inventory vs userspace tooling discrepancy)

**Hypothesis.** An eBPF-based rootkit (LinkPro Hide module, or BPFDoor/Symbiote-class)
is resident on a Linux host and hides its own BPF programs/maps by hooking the
`sys_bpf` syscall, so `bpftool` under-reports the loaded program set. The ground truth
in the kernel's `prog_idr` (and a RAM capture) will list programs that userspace tools
do not.

**Why it works.** The Hide module attaches Tracepoint/Kretprobe programs to
`sys_enter_bpf`/`sys_exit_bpf` and filters `BPF_PROG_GET_NEXT_ID` so iteration skips its
own IDs (the "HIDING NEXT_ID" debug string). Userspace inventory is therefore unreliable
*after* infection, but the program LOAD event and the raw kernel structures are not.

## Data sources
- auditd `bpf` syscall events (`-a always,exit -F arch=b64 -S bpf -k ebpf_load`).
- `bpftool prog show` / `bpftool map show` (JSON) collected at scale.
- Memory capture (LiME / AVML) + Volatility 3 Linux `linux.ebpf` (or `prog_idr` walk).
- Falco/Tetragon program-load telemetry where deployed.

## Analytic steps
1. Pull `bpftool prog show --json` from each host; normalise into a per-host program set
   (type, name, tag, loaded-by PID/comm).
2. Compare each host's userspace program count to the count of `bpf(BPF_PROG_LOAD)` events
   seen in auditd over the same window. A negative delta (more loads than visible programs)
   is the lead.
3. On leads, acquire RAM and walk `prog_idr` (or run Volatility `linux.ebpf`). Any program
   present in the kernel inventory but absent from `bpftool` output is high-confidence
   malicious hiding.
4. Inspect the loading process `comm` for unexpected loaders (shells, `/tmp/*`, Go/Rust
   binaries, container workloads). Cross-reference with H2 (preload) and H3 (knock).

## Expected benign
eBPF observability/security agents (cilium, falco, tetragon, systemd-resolved). Allow-list
them; the residue after subtraction should be near-zero on a clean host.

## Pivots / escalation
A confirmed hidden program → treat host as compromised: snapshot disk + RAM before
remediation, hunt for `/etc/ld.so.preload` (H2) and a magic-packet listener (H3), and
rotate every credential the node's pods could reach.

Linked detections: `sigma/linux_ebpf_program_load_from_unexpected_binary.yml`,
`kql/linkpro_ebpf_load_and_jenkins_cve_2024_23897.kql`.
