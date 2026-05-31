# PEAK Hunts — EVM/DeFi npm typosquat (namikazesarada010206)

**Author:** Jarmi
**Date:** 2026-05-07
**Reference:** https://xygeni.io/blog/evm-defi-npm-typosquatting-attack-steals-developer-keys/

These two hypotheses are designed to triangulate the campaign **even
without the known IOCs** — the goal is to be robust to operator pivot
(new C2 IP, new package names, same TTPs).

---

## H1 — "Builder bait"

**Hypothesis:** Any host with Hardhat / Foundry / Brownie installed
that in the last 7 days has imported a package listed in a
*brand-adjacency squat watchlist* will have generated a burst of
reads against `~/.foundry/keystores/*`, `~/.aws/credentials` and/or
`~/.npmrc` from the same `node` PID inside a 60-second window.

**Why this pattern discriminates:** legitimate libraries (`viem`,
`wagmi`, `ethers`, `web3.js`, `@nomicfoundation/hardhat-*`) **do
not** spontaneously read wallet keystores. Only deployment tools
that the developer invokes **explicitly** do — and the keystore
they open is **one specific file**, not the full list.

**Data to correlate:**

- Source 1: file_event with `InitiatingProcessFileName in (node, ts-node)`
  and `FolderPath` matching the sensitive-paths watchlist.
- Source 2: process_creation of `node` with `package.json` in cwd and
  `hardhat.config.*` / `foundry.toml` / `brownie-config.yaml` present.

**Base query — KQL Defender XDR:**

```kql
let Watch = dynamic([
    "/.ssh/id_","\\.ssh\\id_",
    "/.aws/credentials","\\.aws\\credentials",
    "/.npmrc","\\.npmrc",
    "/.foundry/keystores","\\.foundry\\keystores",
    "/.ethereum/keystore","\\.ethereum\\keystore",
    "/.brownie/accounts","\\.brownie\\accounts"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node","ts-node","ts-node.exe")
| where FolderPath has_any (Watch)
| summarize Reads=dcount(strcat(FolderPath,"/",FileName)),
            Sample=make_set(strcat(FolderPath,"/",FileName), 25),
            Tstart=min(Timestamp), Tend=max(Timestamp)
    by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCommandLine
| where Reads >= 3 and datetime_diff('second', Tend, Tstart) <= 60
| order by Tstart desc
```

**Expected benign rate:** near-zero. If your org has legitimate
`node` scripts that touch those paths (CI helpers, credential
rotation tooling), add them to a per-path/per-host exclusion list.

**Expected malicious signature:** a single `node` PID that within
<60s reads SSH key + wallet keystore + (`.aws/credentials` or
`.npmrc`).

**Action on match:** IR triage §5 — and *first* move funds on
mainnet/L2 before touching the host.

---

## H2 — "IP-only egress from dev tooling"

**Hypothesis:** A host on the dev/CI VLAN that opens TLS toward a
literal IPv4 with no SNI (or empty SNI) from a `node` process is a
strong stealer/C2-in-npm candidate.

**Why this pattern discriminates:** legitimate cloud services
(GitHub, npm registry, Alchemy, Infura, AWS) use domains and
non-empty SNI. A binary that connects to a literal IP with no SNI
and TLS verify off is a **structural signal** of malicious operation
on a low-cost-infra footprint (no DNS, no cert).

**Base query — Zeek (cleanest):**

```bash
# TLS connections from dev VLAN with no SNI to public literal IPv4
zcat ssl.*.log.gz \
  | jq -r 'select(.["server_name"]=="" or .["server_name"]==null)
           | select(.["id.orig_h"] | test("^10\\.42\\."))
           | select(.["id.resp_h"] | test("^(10\\.|172\\.|192\\.168\\.|127\\.|169\\.254\\.)") | not)
           | [.["ts"], .["id.orig_h"], .["id.resp_h"], .["id.resp_p"]] | @tsv'
```

**Base query — Sentinel:**

Use `kql/sentinel_node_outbound_first_seen_ipv4.kql` from this
folder; it covers the "first-seen IPv4 from `node`" case with a
30-day baseline.

**Expected benign rate:** minimal. The few legitimate services that
do TLS-to-literal-IP with no SNI are typically internal
(Kubernetes API, load balancers) — all RFC1918 and excluded by
the filter.

**Expected malicious signature:** `node` PID outbound to a public
IPv4 not seen from this device in the last 30 days. When this
coincides with H1 on the same host it is a **high-confidence**
indicator of the full chain (activation → harvest → exfil).

**Action on match:**

1. Capture a 5-minute pcap around the event.
2. `lsof -p <node_pid>` to bind the file descriptor to the socket.
3. Snapshot `package-lock.json` and `node_modules/` before any
   cleanup.
4. Proceed to README §5 (IR/Forensics).

---

## Minimum required telemetry

| Hunt | Primary source | Alternatives |
|---|---|---|
| H1 | DeviceFileEvents (Defender XDR) | auditd `path` watch + osquery `file_events` |
| H2 | Zeek `ssl.log` | DeviceNetworkEvents / Suricata `tls.sni` (see `suricata/tls_no_sni_ipv4_literal.rules`) |

## High-value combinations

- **H1 ∧ H2** on the same host within <10m → confirmed incident, run full IR.
- **H1 without H2** → possible harvest without exfil (C2 down / attacker waiting) — still an incident.
- **H2 without H1** → possible recon or alternate stealer — investigate live `node_modules`.
