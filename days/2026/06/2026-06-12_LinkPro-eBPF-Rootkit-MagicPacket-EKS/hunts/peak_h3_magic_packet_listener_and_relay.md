# PEAK Hunt H3 — Magic-packet listeners and outbound proxy/relay on internet-facing nodes

**Hypothesis.** An internet-facing Linux node (EKS worker, exposed VM) runs a passive
backdoor that activates on a magic packet (LinkPro Knock: TCP SYN, window 54321) and/or an
outbound proxy/relay (vnt → `vnt.wherewego.top:29872`) that lets the operator reach the host
from any IP. Either gives an inbound foothold that bypasses front-end firewall port logic.

**Why it works.** The Knock module installs XDP (ingress) + TC (egress) programs. On the
magic packet it records the source IP for one hour and rewrites any later packet's
destination port to the internal listener (2233), recomputing the TCP checksum — so the
operator can knock on 443 and still reach 2233 internally, decoupling firewall logs from the
real service. The forward/active variant instead dials out, often through the vnt relay.

## Data sources
- Network sensor on a SPAN/tap upstream of the node (the XDP_DROP means host pcap may miss
  the magic packet — capture before the NIC/host).
- `DeviceNetworkEvents` / NetFlow for outbound to the relay port 29872 and to rotating C2.
- Per-host XDP/TC program inventory (`ip link show`, `bpftool net show`, `tc filter show`).

## Analytic steps
1. On internet-facing nodes, enumerate attached XDP and TC programs (`bpftool net show`,
   `tc -s filter show dev <iface>`). Any XDP/clsact program not attributed to your CNI
   (cilium/calico) is a lead.
2. On a tap upstream of suspect nodes, hunt TCP SYN packets with `tcp.window == 54321`
   (Suricata SID 2026612001). Correlate the source IP with a subsequent connection from the
   same IP to an unusual high port that the host "answers" despite no listener on that port.
3. Sweep outbound flows for TCP 29872 (vnt relay) and for long-lived WebSocket/DNS-tunnel
   sessions from server processes that should not egress.
4. For DNS-tunnel vShell: hunt high-entropy, high-volume TXT/NULL queries to a single
   second-level domain from a server workload.

## Expected benign
Window 54321 occurs occasionally in normal traffic; it is a hunt lead, not a standalone
verdict. CNI-managed XDP/TC programs are expected — attribute and allow-list them.

## Pivots / escalation
A non-CNI XDP/TC program OR a magic-packet+port-rewrite pattern → host compromised: pivot to
H1/H2, image RAM+disk, and assume the operator had interactive access for the activation
window. Rotate credentials reachable from the node and its pods.

Linked detections: `suricata/linkpro_magic_packet_and_c2.rules`,
`kql/linkpro_c2_vshell_vnt_network.kql`.
