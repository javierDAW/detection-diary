# PEAK hunt H2 - Ethereum dead-drop resolver: a process under ~/.solidity reads a contract over public RPC, then opens TLS to a raw IP on 4912 and spawns a persistent sh pty

## Prepare

- **Hypothesis:** a Linux or macOS host that ran the bee-js 13.3.0 / Swarm Desktop 0.56.2 payload now runs the Go backdoor from `~/.solidity/` (`linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, started by `.run.py` / `.run.cjs`), persisted as `~/.config/systemd/user/solidity-langsupport-runner.service` or `~/Library/LaunchAgents/com.solidity.langsupport.runner.plist`. It calls `eth_call` on contract `0xf8a900Db50b3331be6B768bA460BB59f3E40C344` (getter `param1()` selector `0x02d91518` returns the hub; `param2()` selector `0x1f049b68` returns the payload URL) through `rpc.ankr.com` or `cloudflare-eth.com`, then connects to the hub over TLS without certificate validation (historically TCP 4912) and keeps an `sh` pty shell open.
- **Why:** Socket and StepSecurity (2026-11-09) describe this chain; the same contract and the ScreenConnect relay link it to the SleepyDuck Open VSX campaign (Pluto Security, 2026-10-01; link medium confidence, no named actor). A dead-drop resolver means blocklists go stale: the operator rotates the hub by writing a new value to the contract (seven hubs already seen).
- **Honesty:** Go strings (`hubclient.runCommand`, `hubclient.startShellLocked`, `github.com/creack/pty`) are static strings per StepSecurity, not observed behaviour; the module name `evjawbreaker` is from The Hacker News. The backdoor exits under a debugger or VM, so sandbox detonation may show nothing. Exact JSON-RPC request bodies were not published; the selectors above are what to look for if you inspect decrypted RPC traffic.
- **Scope:** Linux and macOS developer hosts and self-hosted runners with EDR (Defender for Endpoint, osquery, auditd / eBPF) and proxy / DNS logs; 2026-11-09 onwards.
- **Confidence:** high for files + persistence + 4912 egress; medium for RPC-gateway-only signal.

## Execute

**Data sources / content:** `sigma/02_solidity_backdoor_dropper_files_and_persistence.yml`, `kql/k1_frameworkmetrics_egress_hub_ips_and_solidity_eth_rpc_dead_drop.kql`, `kql/k2_persistence_solidity_files_screenconnect_service_defender_exclusion_msiexec.kql`, `suricata/bee_js_swarm_c2.rules` (9992004), `yara/bee_js_swarm_sleepyduck.yar` (rules `SleepyDuck_Linked_Solidity_Go_Backdoor`, `SleepyDuck_Linked_Solidity_Persistence_Unit_Or_Plist`).

1. Live triage on a suspected host (read-only):

```bash
# Author: Jarmi
ls -la ~/.solidity/ 2>/dev/null && sha256sum ~/.solidity/* 2>/dev/null
systemctl --user status solidity-langsupport-runner.service 2>/dev/null
cat ~/.config/systemd/user/solidity-langsupport-runner.service 2>/dev/null
# macOS
plutil -p ~/Library/LaunchAgents/com.solidity.langsupport.runner.plist 2>/dev/null
launchctl list | grep -i solidity
# Process tree and sockets: backdoor -> sh with a pty
ps -eo pid,ppid,user,tty,lstart,cmd | grep -E '\.solidity|[s]h$'
ss -tnp 2>/dev/null | grep -E ':4912\b'          # Linux
lsof -nP -iTCP -sTCP:ESTABLISHED | grep -E ':4912\b|solidity'   # macOS / Linux
```

2. Compare hashes with the published values (`linux_amd64` `9b73e7cd...d9696`, `linux_arm64` `b6017768...cc565`, `darwin_amd64` `80d2672e...d250f`, `darwin_arm64` `fae61f31...27358`; full values in `iocs.csv`).
3. Run k1 branches `SolidityEthRpcDeadDrop` and `SolidityProcessToPort4912`: an RPC gateway call followed within seconds by a raw-IP connection from the same initiating process is the dead-drop pattern.
4. Read the current hub yourself (read-only `eth_call`, no transaction) so blocklists stay current:

```bash
# Author: Jarmi
curl -s https://cloudflare-eth.com -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xf8a900Db50b3331be6B768bA460BB59f3E40C344","data":"0x02d91518"},"latest"]}'
# Decode the ABI string in the result (offset, length, bytes) and add the new hub to Suricata / k1
```

5. On macOS, check for cleared quarantine on the dropped binaries (`xattr -l ~/.solidity/*`) and Unified Log entries for the LaunchAgent load.

## Act

- **Expected benign:** Solidity tooling using a `~/.solidity` folder (no `linux_*` / `darwin_*` binaries, no runner unit); wallets and dApps calling `rpc.ankr.com` / `cloudflare-eth.com` from browsers or Node processes outside `.solidity`.
- **Action on match:** isolate the host (the operator has an interactive shell), capture memory and the `~/.solidity` folder, disable and remove the unit / LaunchAgent only after imaging, block current + historical hubs and re-read the contract daily. Rotate every credential reachable from the user account (SSH, cloud, npm, GitHub, wallet keys, Swarm keys). Rebuild rather than clean.
- **Escalation:** shell history and pty child processes show what the operator ran; pivot on any new hub IP across the fleet.
- **Exit criteria:** no `~/.solidity` artefacts, unit or LaunchAgent fleet-wide; no traffic to any value ever returned by the contract; credentials rotated.
