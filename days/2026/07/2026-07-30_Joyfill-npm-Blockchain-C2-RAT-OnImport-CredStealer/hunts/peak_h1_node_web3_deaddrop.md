# PEAK Hunt H1 — A build/CI node process resolving C2 from a blockchain dead drop

**Hypothesis.** A compromised npm package (Joyfill-class) imported in our build, CI or a developer session ran an on-import loader that resolved its live C2 from an on-chain transaction, so a `node` process reached public blockchain APIs (Tron / Aptos / BNB Smart Chain) that our software has no legitimate reason to contact.

**Prepare (data).** Endpoint network telemetry with process attribution: Defender XDR `DeviceNetworkEvents`, Sysmon EID 3, or CI egress logs (StepSecurity Harden-Runner baseline). Ensure `node` process→destination mapping is retained.

**Execute (analytic).**
```kql
let chainhosts = dynamic(["api.trongrid.io","fullnode.mainnet.aptoslabs.com","bsc-dataseed.binance.org","bsc-rpc.publicnode.com"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteUrl has_any (chainhosts)
| summarize Hits=count(), Hosts=make_set(RemoteUrl,10), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by LastSeen desc
```

**Act.** For each hit, pull the surrounding process tree and the project's lockfile. Grep lockfiles for a `2773` prerelease of `@joyfill/components`/`@joyfill/layouts` and, more generally, for any package/version installed just before the blockchain callout. Treat the host as compromised: rotate credentials present on it, and inspect developer-tool files for injected loader stubs.

**Notes / pitfalls.** Legitimate web3 tooling and tests also call these APIs — baseline them per project/host and allowlist. The discriminators are: the calling process is a build/test/dev `node` (not a web3 app), the callout clusters with an `npm install`/import event, and it is followed by a plain-HTTP Socket.IO connection to an unfamiliar IP.

**Refine.** Promote confirmed project+host pairs to a scheduled analytic; feed any resolved C2 IPs into H2 and the Suricata ruleset; add a Cooldown/allowlist control on newly published package versions.
