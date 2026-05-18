# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

---

## 2026.05.18 — Day 21 — Silver Fox ABCDoor tax-themed phishing in India and Russia (Kaspersky Securelist)

### Added
- `days/2026-05-18_SilverFox-ABCDoor-Tax-Phishing/` — Kaspersky Securelist disclosure (30-April-2026) of an active Silver Fox campaign delivering the new ABCDoor Python implant through tax-themed phishing impersonating the Indian Income Tax Department and the Russian Federal Tax Service. The chain layers a modified RustSL loader (with novel Phantom Persistence shutdown-signal hijack and Halo's Gate indirect syscalls), the actor's signature ValleyRAT / Winos 4.0 plugin chain, and a Cython-compiled `appclient.core` Python backdoor abusing the Tailscale brand for its install directory. More than 1 600 malicious emails recorded in January–February 2026. Targets: industrial, consulting, retail and transportation organisations across India, Russia, Indonesia, South Africa, Cambodia and Japan (added to geofence 2026-01-19). Cluster aliases tracked across vendors: Silver Fox, SwimSnake, Void Arachne, UTG-Q-1000, Monarch, The Great Thief of Valley.
- Sigma (3): `silverfox_pythonw_appclient_persistence.yml` — pythonw.exe -m appclient with install path under LOCALAPPDATA\appclient or ProgramData\Tailscale; `silverfox_rustsl_phantom_persistence_shutdown_hijack.yml` — rsl_debug.log file event in user-writable directory; `silverfox_appclient_scheduled_task_registration.yml` — schtasks /create /tn AppClient with the appclient action (critical).
- KQL (3): `silverfox_abcdoor_persistence_chain.kql` — joins HKCU Run\AppClient writes with pythonw -m appclient executions and the AppClient scheduled task within 24 hours; `silverfox_valleyrat_c2_egress.kql` — egress to the known Silver Fox C2 IPs and domains by non-browser processes; `silverfox_rust_loader_pdf_icon_archive_extraction.kql` — PDF-icon EXE extracted from a tax-themed RAR or ZIP archive.
- YARA (1 file, 2 rules): `ABCDoor_AppClient_Python_Implant_2026` (Cython anchors plus manager classes plus appclient anchors plus ddagrab screen API); `RustSL_Loader_Phantom_Persistence_2026` (verbatim banner plus geofence service strings plus country allow-list).
- Suricata (1 file, 6 sids 8210001-8210006): DNS anchors for abc.haijing88.com, mcagov.cc, abc.fetish-friends.com; TCP egress to 207.56.138.0/24:6666 (ValleyRAT C2); HTTP plugin pulls from 154.82.81.0/24 with YD/YN URI pattern; HTTP User-Agent PythonDownloader.
- PEAK hunts (3): H1 — PDF-icon EXE extracted from a tax-themed archive followed by pythonw -m appclient within thirty minutes; H2 — rsl_debug.log file write paired with a geofence service callout within five minutes; H3 — ValleyRAT plugin load or 207.56.138.0/24:6666 egress followed by Python implant install within six hours.
- `iocs.csv` (42 entries) — payload-host domains, ValleyRAT C2 IPs, RustSL and ABCDoor MD5 hashes across seven implant versions, registry keys, install paths, mutex, downloader User-Agent string, Phantom Persistence banner, RSL_STEG_2025_KEY, plus operator notes on geofence coverage, sector telemetry and cluster aliases.
- `kill_chain.svg` — GitHub-friendly adaptive light/dark palette diagram with viewBox 880x1180, nine numbered stages on the victim host lane (phishing through Socket.IO C2), an attacker C2 cluster panel on the right anchoring payload host, ValleyRAT TCP C2 and plugin C2 plus operator playbook and alias set, bidirectional yellow C2 arrows on stages 5, 6 and 9, and a detection-anchors footer mapping every Sigma, KQL, YARA and Suricata deliverable.

### Pedagogy
- The Tailscale brand-abuse path anchor `C:\ProgramData\Tailscale\pythonw.exe -m appclient` is a near-zero-FP signal because a genuine Tailscale install lives in `C:\Program Files\Tailscale\` and does not need a Python interpreter.
- Phantom Persistence (RegisterApplicationRestart plus SetProcessShutdownParameters plus EWX_RESTARTAPPS) is the cleanest 2026 example of Windows API as persistence primitive — no registry, no scheduled task, no service, only the application-restart manager.
- Halo's Gate indirect syscalls defeat user-mode EDR hooks but ETW-TI plus kernel callbacks still see everything; treat hosts with clean ntdll.dll loads but sparse EDR telemetry as retrospective hunting candidates.
- Silver Fox is the canonical 2026 hybrid-cybercrime-APT attribution-ambiguity case: China nexus origin, espionage-style TTPs, cybercrime-style monetisation paths — attribution must operate at the operational layer rather than at the country layer alone.

---

## 2026.05.16 — Day 20 — Cisco Catalyst SD-WAN vHub auth bypass (CVE-2026-20182) — UAT-8616 + ten post-compromise clusters

### Added
- `days/2026-05-16_Cisco-SDWAN-vHub-AuthBypass-UAT8616/` — Rapid7 Labs and Cisco Talos joint disclosure (14-May-2026) of CVE-2026-20182, a CVSS 10.0 authentication bypass in `vdaemon` over DTLS UDP/12346 affecting Catalyst SD-WAN Controller (formerly vSmart) and Manager (formerly vManage). `vbond_proc_challenge_ack()` has no verification branch for `device_type == 2` (vHub) and falls through to `peer->authenticated = 1` without any certificate check; the actor then uses `MSG_VMANAGE_TO_PEER` (msg_type=14) to append an attacker SSH public key to `/home/vmanage-admin/.ssh/authorized_keys` and logs in via NETCONF on TCP/830. Cisco PSIRT confirmed limited in-the-wild exploitation by UAT-8616 (medium-high confidence China-nexus via ORB-network infrastructure overlap, three-year operational continuity from CVE-2026-20127 since 2023). In parallel Talos documented ten distinct activity clusters opportunistically exploiting the unpatched February-2026 chain (CVE-2026-20133 / 20128 / 20122) since March 2026 with ZeroZenX Labs' public PoC, deploying JSP webshells (Godzilla, Behinder, XenShell), AdaptixC2 with custom `shadowcore` banner, Sliver mTLS, NimPlant-variant `agent1` (AI-modified clone with custom `/api/v1/*` REST), gsocket GSRN tunneling, XMRig miners, and a vManage credential extractor. Sixth SD-WAN zero-day exploited in 2026.
- Sigma (3): `sdwan_vdaemon_vhub_peering_anomalous.yml` — VDAEMON `peer-type:vhub` + `new-state:up` from non-allowlisted public-ip; `sdwan_netconf_vmanage_admin_ssh_login.yml` — NETCONF TCP/830 SSH public-key login as `vmanage-admin` from non-orchestrator source; `sdwan_authorized_keys_modification_vmanage_admin.yml` — file_event writes to `/home/vmanage-admin/.ssh/authorized_keys` (critical level).
- KQL (3): `sdwan_vhub_peering_then_netconf_login.kql` — join of vHub peering and NETCONF login per appliance within a 24-hour window; `sdwan_post_compromise_webshell_jsp_drop.kql` — `DeviceFileEvents` detection of the six known cluster webshell filenames; `sdwan_post_compromise_c2_egress_known_clusters.kql` — `DeviceNetworkEvents` egress to the curated cluster IP set (clusters 1-10).
- YARA (1 file, 2 rules): `SDWAN_AdaptixC2_Implant_Shadowcore_2026` (ELF + custom `shadowcore` banner + Cluster 5 C2 anchors + filesize cap); `SDWAN_NimImplant_AgentOne_2026` (ELF + Nim anchors + custom `/api/v1/*` REST paths + Cluster 8 C2 anchors).
- Suricata (1 file, 7 sids 8200001-8200007): AdaptixC2 shadowcore IP/port; Sliver mTLS C2 IP/port; XMRig downloader and Cobalt Strike host; NimPlant-variant C2 IP/port; NimPlant-variant custom REST URI; Replit dropper SNI; webshell operator IPs for Clusters 1-4.
- PEAK hunts (3): H1 — anomalous vHub peering on Catalyst SD-WAN Controllers; H2 — authorized_keys drift on `vmanage-admin` across the SD-WAN fleet; H3 — JSP webshell drop plus egress to Talos-curated cluster C2.
- `iocs.csv` (47 entries) — CVE anchors, file paths, syslog string anchors, the ten clusters' operator IPs and SHA256s for AdaptixC2 / Sliver / NimPlant-variant / KScan / gsocket / XMRig / credential extractor, webshell filenames, Cisco port inventory and Talos Snort SID references.
- `kill_chain.svg` — adaptive GitHub light/dark palette, viewBox 880x1080, eight numbered stages on the victim Catalyst SD-WAN Controller lane (reconnaissance, vHub fallthrough exploit, SSH key injection, NETCONF SSH login, root downgrade-chain, log truncation, post-compromise tooling, control-plane impact), bidirectional yellow C2 arrows to the AdaptixC2 / Sliver / NimPlant-variant cluster panel, separate webshell-operator and mining/tunneling panels, and a detection-anchors footer mapping each Sigma / KQL / YARA / Suricata deliverable.

### Pedagogy
- A missing `else` default is an authentication primitive. Every device-type-specific branch in `vbond_proc_challenge_ack()` is sound; the bug is the absence of a default reject path. Auth-state machines must end in `goto LABEL_REJECT` unless every branch has explicitly returned success.
- Append-mode file writes are stealth persistence. `fopen("authorized_keys","a+")` keeps legitimate keys in place — detection must be drift-based on fleet-wide SHA256 baselines, not content-based.
- Two exploitation populations on one product: targeted UAT-8616 versus opportunistic Clusters 1-10. Same control-plane appliance, different tradecraft, different IR posture (re-image vs. fleet-wide credential rotation).
- ORB-network infrastructure overlap is high-signal CTI for China-nexus attribution per Mandiant; Talos's note on UAT-8616 makes it the most concrete attribution anchor in this disclosure.
- Edge-device control planes are 2026's preferred persistent foothold for state-nexus actors — Days 3 and 20 of this repo are bookends of that pattern.

---

## 2026.05.15 — Day 19 — EtherRAT + TukTuk → The Gentlemen ransomware (DFIR Report TB40048)

### Added
- `days/2026-05-15_EtherRAT-TukTuk-Gentlemen/` — The DFIR Report's Flash Alert TB40048 (11-May-2026) documenting an April-2026 intrusion in which the **EtherRAT** implant (DPRK-linked lineage first surfaced by Sysdig in December 2025 via CVE-2025-55182 React2Shell on Linux, ported to Windows by an Atos-mapped campaign in March 2026 across 44 GitHub facades impersonating Sysinternals tools) is co-deployed with **TukTuk**, a brand-new framework that Evangelos G's parallel analysis identifies as **AI-generated** based on a symmetric multi-transport bus, inconsistent naming across modules, redundant generic exception handling, and a fully-wired but unused Arweave dead-drop resolver. The operator is e-crime — **The Gentlemen RaaS** affiliate — chaining EtherRAT (Run-key persistence under `AppResolver` with `conhost --headless node.exe <random>.cfg`, Ethereum smart contract C2 resolution through `1rpc.io` to rotating TryCloudflare tunnels, AES-256-CBC layered configs, `AsyncFunction` constructor as RCE primitive, `/api/reobf/` runtime self-overwrite), TukTuk (DLL side-loading under signed Greenshot / SyncTrayzor / DocFX / Cake with a fake `log4net.dll`, multi-transport SaaS C2 across ClickHouse Cloud, Supabase, Ably, Dropbox, and GitHub Issues, plus the Arweave Drive-Id `a6278417-39f4-407e-90bf-599f74726e66` dead drop), GoTo Resolve installed laterally on DCs and tier-0 servers as an RMM-as-backdoor, NetExec `nxc -M lsassy` plus `comsvcs.dll` ordinal `#+0000` for LSASS dumps and `--ntds` for AD extraction, Rclone to Wasabi cloud storage with aggressive multi-thread tuning for exfiltration, and a final domain-wide ransomware detonation via a malicious GPO that drops staged ransomware binaries into `\\<dc>\SYSVOL\<domain>\NETLOGON\` and fans out via scheduled tasks across the AD environment. Dwell time approximately three days. Genealogy: continues the Gentlemen track from Day 1 (`days/2026-04-28_TheGentlemen-SystemBC/`) with an evolved toolchain (SystemBC + Brute Ratel to EtherRAT + TukTuk + GoTo Resolve).
- Sigma (3): `etherrat_node_headless_appdata.yml` — `node.exe` or `conhost.exe --headless` from AppData / Temp with a `.cfg` or `.ini` argument; `tuktuk_sideload_signed_apps_log4net.yml` — helper DLL (`log4net.dll`, `Newtonsoft.Json.dll`, `System.Net.Http.dll`) loaded by Greenshot / SyncTrayzor / DocFX / Cake from non-install paths; `lsass_dump_comsvcs_ordinal.yml` — LSASS minidump via `rundll32 comsvcs.dll #+0000` ordinal with the canonical `tasklist | find "lsass"` PID lookup (critical level).
- KQL (3): `etherrat_staging_chain_nodejs_ethereum.kql` — MSI or cmd downloads `nodejs.org/dist` plus egress to Ethereum RPC providers (`1rpc.io`, `ethereum.publicnode.com`, `mainnet.infura.io`, `rpc.ankr.com`) within a thirty-minute window; `tuktuk_saas_exotics_burst_atypical_host.kql` — egress to ClickHouse Cloud, Supabase, Ably, Arweave, 1rpc.io, or TryCloudflare from a host without a thirty-day baseline; `gotoresolve_install_dc_plus_gpo_drop.kql` — GoTo Resolve install on a DC, file server, hypervisor, or app server tier joined to a SYSVOL or NETLOGON file write within twenty-four hours.
- YARA (1 file, 2 rules): `TukTuk_log4net_sideload_2026` — heuristic combining MZ + .NET CLR magic + log4net impersonation + three or more multi-transport bus anchors (ClickHouse, Supabase, Ably, Dropbox, GitHub Issues) + at least one Arweave dead-drop anchor (`arweave.net`, `g8way.io`, or the literal `Drive-Id`), capped at five MB; `TukTuk_log4net_known_hashes_2026` — exact SHA256 anchor for the DFIR Report `log4net.dll` (`19021e53b9929fdf4b7d0e0707434d56bb73c1a9b7403c8837b44d1c417198dc`).
- Suricata (1 file, 8 sids 8190001-8190008): DNS `1rpc.io`, DNS `arweave.net`, DNS `g8way.io`, TLS SNI `trycloudflare.com`, TLS SNI `clickhouse.cloud`, TLS SNI `supabase.co`, TLS SNI `wasabisys.com`, DNS `borjumaniya.store`. Complements the ET OPEN sids 2058788, 2058739, 2034552, 2058175, 2060250, 2050130, 2061992, 2061989, 2046657.
- PEAK hunts (3): H1 — Headless Node from AppData reaching Ethereum RPC or TryCloudflare within five minutes; H2 — Signed userland binary side-loading from non-install paths; H3 — GoTo Resolve installed on a DC plus a SYSVOL or NETLOGON write within twenty-four hours (the lethal pre-ransomware fan-out chain).
- `iocs.csv` — 47 entries covering all six payload hashes in SHA256, MD5, and SHA1 forms, the 11 TryCloudflare tunnel URLs, both Ethereum smart contract addresses, the Arweave Drive-Id, all SaaS and HTTP C2 domains observed in this campaign and in a related one, the React2Shell CVE-2025-55182 upstream anchor, the Run-key path, the Softperfect Network Scanner canonical path, and three operational notes covering SaaS allowlisting, TryCloudflare IP rotation, and the disk-vs-RAM forensics caveat for the `/api/reobf/` self-overwrite.
- `kill_chain.svg` — GitHub-friendly adaptive light / dark palette diagram with viewBox 880x1280, eleven numbered stages on the victim host lane (initial access through impact), an attacker C2 panel on the right showing the Ethereum smart contracts, the eleven TryCloudflare tunnels, the TukTuk multi-transport bus, and the Arweave dead-drop block, plus a separate exfil destination panel for Wasabi, bidirectional yellow arrows for the EtherRAT and TukTuk C2 channels, and a bottom detection-anchors box mapping every Sigma, KQL, YARA, Suricata, and hunt deliverable.

### Pedagogy
- *Three layers of modern tradecraft converge in one operation*: blockchain-resolved C2 (Ethereum smart contracts plus Arweave dead drop), SaaS-abusing C2 (ClickHouse, Supabase, Ably, Dropbox, GitHub Issues), and AI-generated payloads. Defenders cannot ignore any layer in isolation.
- *Operator vs. tooling attribution*: EtherRAT carries DPRK fingerprints but the operator here is e-crime. Attribution is best read at the operational layer; implants travel between actors as commodity tooling.
- *RMM-as-backdoor is the dominant lateral pattern in 2026 e-crime*: GoTo Resolve here, ScreenConnect in Akira intrusions, AnyDesk in Black Basta, TeamViewer in Conti-era. Domain controllers and other tier-0 systems must never carry third-party RMM.
- *GPO plus SYSVOL is the fastest ransomware fan-out path*. Detection on SYSVOL writes plus tier-0 RMM installs is the last reliable moment before domain-wide encryption. Audit GPO changes as if they were code commits.
- *Always RAM-dump before reboot*: the runtime self-overwrite of EtherRAT plus TukTuk's in-memory transport configuration mean disk artefacts are stale snapshots. Disk forensics alone is insufficient for this implant class.
- *AI-generated malware has stylistic fingerprints*: symmetric multi-transport buses, inconsistent naming across modules, redundant generic exception handling, fully-wired but unused capabilities. Build a detection-engineering checklist for these style anchors — they will appear in more frameworks across the rest of 2026.

---

## 2026.05.14 — Day 18 — Mini Shai-Hulud TeamPCP Mega-Campaign (CVE-2026-45321)

### Added
- `days/2026-05-14_Mini-Shai-Hulud-TeamPCP-Mega-Campaign/` — TeamPCP supply-chain worm campaign that compromised 170+ npm/PyPI packages (404 malicious versions, 518M cumulative downloads affected) via a GitHub Actions `pull_request_target` Pwn Request against TanStack/router. The attacker fork `zblgg/configuration` opened a PR that triggered the base-repo workflow context, poisoned the pnpm cache, and read the GitHub Actions OIDC JWT directly from runner process memory (`/proc/<pid>/mem`). The extracted token was used to publish malicious versions under TanStack's legitimate pipeline identity — the first documented case of SLSA Build Level 3 provenance forgery in an active supply-chain worm. The postinstall hook `router_init.js` (SHA256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`) downloads the Python zipapp payload `transformers.pyz` from `git-tanstack[.]com`. The payload harvests 100+ credential paths (AWS, GCP, Azure, Kubernetes, npm, PyPI, GitHub CLI, SSH, `.ethereum/keystore`, `.foundry/keystores`, 1Password, Bitwarden, Signal, Slack, VPN configs, shell history) and exits if the system locale is Russian or CPU count is below 4 (T1480). The companion PyPI package `mistralai==2.4.6` activates on `import mistralai` and probabilistically executes `rm -rf /` (1-in-6 odds) on systems geolocated to Israel or Iran. Persistence via a `gh-token-monitor` daemon (systemd on Linux; LaunchAgent on macOS) that polls GitHub every 60 seconds using a stolen token and triggers `rm -rf ~/` on HTTP 40x token-revocation responses. **Critical IR constraint: isolate the host before revoking any GitHub or npm tokens — revocation fires the destructor.** C2 infrastructure: `83.142.209.194/ingest` (primary credential exfiltration), `git-tanstack[.]com` (payload host), `*.getsession.org` (Session messenger fallback), GitHub API dead drops with Dune-themed repository names. CVE-2026-45321 CVSS 9.6.
- Sigma (2): `mini_shai_hulud_transformers_pyz_exec.yml` — process_creation detecting python3/python executing `/tmp/*.pyz` or a command line containing the known C2 IOCs; `mini_shai_hulud_gh_token_monitor_persistence.yml` — file_event detecting creation of `/etc/systemd/system/gh-token-monitor*` or `~/Library/LaunchAgents/com.github.token-monitor.plist` (level: critical, no expected false positives).
- KQL (2): `mini_shai_hulud_credential_burst_after_install.kql` — Defender XDR `DeviceFileEvents` detecting a burst of four or more distinct credential file reads within a five-minute window from an npm, pip, or python3 process; `mini_shai_hulud_attack_window_install_check.kql` — installs of compromised packages during the attack window (2026-05-11 19:20 UTC to 2026-05-12 14:00 UTC) joined with C2 egress within thirty minutes.
- YARA (1 file, 2 rules): `MiniShaiHulud_TransformersPyz_TeamPCP_2026` — PK zipapp magic at offset 0, `__main__.py` entry point, at least one C2 / guardrail anchor, and at least two of the four high-value credential path strings; `MiniShaiHulud_GhTokenMonitor_Daemon_2026` — service name anchor plus the destructive `rm -rf ~/` string or the poll-and-plist combination.
- Suricata (1 file, 5 sids 6001401-6001405): DNS query for `git-tanstack.com`; HTTP GET for `/tmp/transformers.pyz`; any traffic to `83.142.209.194`; HTTP POST to `/ingest` on the C2 IP; DNS query for `getsession.org`.
- PEAK hunt H1 (`hunts/peak_h1_compromised_package_install.md`): "Provenance-Clean Poison" — identifies hosts that installed affected packages during the attack window and shows post-install anomalies (credential burst, C2 egress, daemon creation) that discriminate malicious from benign installs despite valid SLSA provenance.
- `iocs.csv` — 15 entries covering the C2 domain, exfiltration IP, `router_init.js` SHA256, Session messenger fallback, malicious PyPI versions, daemon service names, CVE, and the attack window note.
- `kill_chain.svg` — GitHub-friendly adaptive light/dark palette diagram with 7 numbered stages on the victim host lane (Pwn Request and cache poisoning → OIDC token extraction → SLSA provenance forgery → payload delivery with bidirectional yellow arrow to the C2 cluster → credential harvest → gh-token-monitor persistence → exfiltration and destructive tripwire), a C2 cluster panel on the right showing all three channels and key IOC anchors, and a detection-anchors footer with the isolation rule, crypto-wallet rule, and SLSA caveat.

### Pedagogy
- *SLSA Build Level 3 is not an authorization guarantee.* The standard certifies the build process, not whether the triggering workflow was authorized or protected by branch protection rules. `npm audit signatures` passing is a necessary but insufficient condition for package integrity.
- *`pip install --no-deps` does not mitigate import-time payloads.* `mistralai==2.4.6` activates on `import mistralai` regardless of how the package was installed.
- *Isolate before you revoke.* The `gh-token-monitor` daemon fires `rm -rf ~/` the moment the GitHub token is revoked. Revocation must come after network isolation and RAM capture, not before.
- *Move on-chain funds before host cleanup.* Assume that `.ethereum/keystore` and `.foundry/keystores` were exfiltrated. Wallet keys should be rotated from a clean machine before the compromised host is re-imaged.
- *The lockfile is the first source of truth.* Verify package hashes against the npm provenance transparency log for the exact versions installed during the attack window.

---

## 2026.05.13 — Day 17 — Semantic Kernel Prompt-to-RCE (CVE-2026-26030 and CVE-2026-25592)

### Added
- `days/2026-05-13_SemanticKernel-Prompt2RCE/` — Microsoft Defender Security Research disclosure (7-May-2026) of two pre-patch vulnerabilities in Microsoft's open-source agent framework `semantic-kernel` (27K stars, foundational for Copilot Studio, M365 Copilot extensions and Azure AI Foundry integrations). CVE-2026-26030 (CVSS 9.8) lives in the Python `InMemoryVectorStore` default filter, which interpolates a model-controlled string into a Python lambda executed under `eval()` with an empty `__builtins__`; a Python AST traversal payload reaches `BuiltinImporter.load_module('os').system(...)` and pops a host shell despite a pre-`eval` validator that blocklists names like `eval`, `exec`, `open` and `__import__`. CVE-2026-25592 (CVSS 7.5) lives in the .NET SDK `SessionsPythonPlugin`, where `DownloadFileAsync` was accidentally marked with `[KernelFunction]`; the AI model can invoke it to write attacker-generated payloads from an Azure Container Apps dynamic Python session directly to the host Windows Startup folder, defeating sandbox isolation. The symmetric `UploadFileAsync` primitive enables arbitrary host-to-sandbox file read of `id_rsa`, `~/.aws/credentials`, `%APPDATA%\Microsoft\Credentials`, and similar. Patched in `semantic-kernel >= 1.39.4` (PyPI) and `Microsoft.SemanticKernel >= 1.71.0` (NuGet). The class of bug — untrusted natural-language input mapped to system tools — is the structural successor of SQL string concatenation in agent runtimes.
- Sigma (3): shell or recon LOLBin spawned by a Semantic Kernel agent runtime; agent runtime writes to a Windows Startup folder (T1547.001); agent application log message contains Python AST traversal anchors (`__subclasses__`, `BuiltinImporter`, `load_module`, `__class__.__bases__`).
- KQL (3): Defender XDR `DeviceProcessEvents` extension of the Microsoft-published advanced hunting query with a broader LOLBin set; Defender XDR `DeviceFileEvents` Startup folder write by an agent runtime; Sentinel custom log heuristic for AST traversal anchors in agent runtime logs (placeholder `<add_known_sk_table>` for tenant-specific ingest table).
- YARA (1 file, 2 rules): `SK_PromptInjection_AST_Traversal_Heuristic_2026` (AST-traversal band) and `SK_SessionsPython_SandboxEscape_Heuristic_2026` (Startup folder + DownloadFileAsync / SessionsPythonPlugin / UploadFileAsync band).
- Suricata (1, 3 sids 8140001-8140003): AST traversal payload in HTTP request body; DownloadFileAsync targeting the Windows Startup folder; UploadFileAsync targeting `\.ssh\`, `\.aws\`, or `\AppData\Roaming\Microsoft\Credentials`.
- PEAK hunts (3): H1 — agent runtime spawning shell / recon LOLBin in a short window after a tool call; H2 — agent service principal in Entra ID emitting token requests for scopes outside its 30-day baseline; H3 — agent egress to destinations outside the tenant allowlist of model endpoints, declared tools and registered MCP servers.
- `iocs.csv` — 14 entries covering both CVEs, the canonical AST traversal string anchors, the misexposed `[KernelFunction]` names, the Startup folder path sink, the patch baselines, the Microsoft CTF harness and the patch PR.
- `kill_chain.svg` — GitHub-friendly adaptive light / dark palette diagram with 8 numbered stages on the victim agent host (prompt injection through impact via agent identity), an attacker-and-sandbox panel on the right (prompt source plus Azure Container Apps dynamic Python session that hosts the SessionsPythonPlugin escape), a patch baseline panel and a bottom detection-anchors box mapping each stage to the rules in `sigma/`, `kql/`, `yara/`, `suricata/` plus the three PEAK hunts.

### Pedagogy
- *The LLM is not a security boundary.* Treat any tool parameter the model can influence as attacker-controlled, exactly as you would treat any HTTP request parameter in a web app.
- *Allowlists beat blocklists in dynamic languages.* Python's type system is flexible enough to reintroduce every restricted operation via alternate syntax — `obj['__class__']` vs `obj.__class__`, `__subclasses__()`, `__bases__`. A four-line AST allowlist beats a fifty-line blocklist.
- *`[KernelFunction]` is the modern equivalent of "marked as public".* Every method so decorated is part of the attack surface. Audit your `Http*`, `File*`, `Process*`, `Db*` exposure explicitly.
- *Egress from an agent host is indistinguishable from legitimate tool traffic at the transport layer.* Defenders must rely on a tenant-curated destination allowlist; the discriminator is the FQDN, not the protocol or the user agent.
- *Couple framework-level guardrails with host-level EDR.* AST allowlist plus path canonicalisation at the framework. Process-tree, file-event and identity-token telemetry at the host. Neither layer is sufficient alone.

---

## 2026.05.12 — Day 16 — Qilin EDR Killer msimg32.dll four-stage loader and BYOVD chain

### Added
- `days/2026-05-12_Qilin-EDR-Killer-msimg32/` — Cisco Talos disclosure (2-April-2026) of the multi-stage loader that Qilin (alias Agenda) and Warlock ransomware operators side-load under `FoxitPDFReader.exe` to disable endpoint detection and response (EDR) before encrypting victims. The `msimg32.dll` loader runs four stages: Stage 1 builds a slot-policy table over `ntdll` Nt* exports, overwrites the `.mrdata` exception dispatcher slot via `LdrProtectMrdata` and uses Halo's Gate-style scanning of clean neighbouring syscall stubs to bypass user-mode hooks; Stage 2 maps a paging-file-backed section with two views (RW + RWX) and IAT-hooks `ExitProcess` so the next stage detonates only after the host process exits cleanly; Stage 3 abuses VEH plus hardware breakpoints on `NtOpenSection` and `NtMapViewOfSection` to stack-pivot through `LdrpMinimalMapModule` and map the embedded PE on top of `shell32.dll` in memory (with a provocative `hasherezade_*.dll` string in the path); Stage 4 drops two drivers — `rwdrv.sys` (a renamed copy of `ThrottleStop.sys` signed by TechPowerUp LLC, providing physical-memory read/write IOCTLs) and `hlpdrv.sys` (a purpose-built malicious helper exposing `IOCTL 0x2222008` to unprotect and terminate processes). The Stage 4 PE iterates a hardcoded list of more than 300 EDR drivers, locates kernel callbacks like `cng!CngCreateProcessNotifyRoutine` via the Superfetch class of `NtQuerySystemInformation` plus a Page Frame Number metadata vector, and unregisters them by direct physical-memory writes before terminating the EDR processes themselves. Recent Qilin victims include Cushman & Wakefield (4-May-2026), Imex International and DL Cohen Construction (both 8-May-2026); Qilin holds the #1 RaaS leaderboard for the third consecutive quarter with 338 victims in Q1 2026.
- Sigma (3): `msimg32.dll` image_load from outside System32 / SysWOW64 / WinSxS; `rwdrv.sys` / `hlpdrv.sys` / mis-placed `ThrottleStop.sys` driver load with known SHA-256 anchors; `sc.exe create` or registry write under `\Services\rwdrv` or `\hlpdrv` as a kernel driver service install.
- KQL (3): Defender XDR — non-system-path `msimg32.dll` image_load joined with `rwdrv.sys` / `hlpdrv.sys` file drop within 30 minutes; Defender XDR — suspicious driver load followed by EDR telemetry quiescence (`DeviceProcessEvents` count drop) within 15 minutes; Defender XDR — `FoxitPDFReader.exe` running from non-install paths and loading `msimg32.dll`.
- YARA (1 file, 2 rules): `Qilin_EDR_Killer_msimg32_Heuristic_2026` (forwarder strings + Halo's Gate Nt* and `LdrProtectMrdata` anchors + VEH `NtOpenSection` / `NtMapViewOfSection` / `LdrpMinimalMapModule` anchors + provocative `hasherezade` string + PE/MZ magic + filesize cap), and `Qilin_EDR_Killer_Known_Hashes_2026` (high-confidence SHA-256 anchors from Talos for `msimg32.dll`, `rwdrv.sys`, `hlpdrv.sys` and the Stage 4 EDR killer PE).
- Suricata (1, 3 sids 8120001-8120003): file-name anchors for `rwdrv.sys`, `hlpdrv.sys` and `msimg32.dll` delivered over plain HTTP into the home network.
- PEAK hunts (3): H1 — Foxit PDF Reader as a side-load vehicle for the loader; H2 — retroactive sweep for hosts with a kernel driver load followed by EDR telemetry gap; H3 — kernel callback baseline drift detection (ELAM-style ground truth).
- `iocs.csv` — 12 file hashes (SHA-256, SHA-1, MD5) for the four artefacts, plus `IOCTL 0x2222008`, the `hasherezade` string anchor, transient drop paths, kernel driver service registry anchors, and operator notes.
- `kill_chain.svg` — adaptive light/dark palette diagram with 8 numbered stages on the victim host (Initial Access through `hlpdrv.sys` IOCTL terminate-protected-process), an attacker C2 / ransomware panel on the right (Qilin operator playbook, recent victims, driver IOC anchors, post-loader chain), and a bottom detection anchors box mapping each stage to the rules in `sigma/`, `kql/`, `yara/`, `suricata/` and the three PEAK hunts.

### Pedagogy
- *EDR telemetry gap is the highest-confidence signal you have.* When the agent goes silent, the SIEM has to fire — design out-of-band heartbeats and correlate gaps with kernel-driver events.
- *BYOVD has a familiar shape: a legitimate-signed driver plus a purpose-built helper driver.* The helper is often the cleaner anchor because it lacks any legitimate use case (`hlpdrv.sys` here, `nseckrnl.sys` in Warlock, `truesight.sys` in Akira and DragonForce).
- *DLL side-loading via signed userland apps remains a recurring pattern* (Foxit, ScreenConnect, Yandex, VMtools, Communicator). Lock down portable executables and force managed MSI installs.
- *Halo's Gate-style user-mode-hook bypass means EDR user-mode hooks alone are insufficient.* Defenders need ETW-TI plus kernel callback baselining; the bypass works precisely because the kernel only checks `eax` for the syscall ID, not which exported stub initiated the call.
- *Re-image, never clean.* Once a host has had its kernel callbacks unhooked and its EDR killed, there is no ground truth about what else the operator dropped.

---

## 2026.05.11 — Maintenance — Full README and kill_chain.svg rebuild across all 15 days

### Changed
- Every `days/<slug>/README.md` from Day 1 (TheGentlemen + SystemBC) through Day 15 (UAT-8302 China-nexus espionage) now follows the canonical 15-section standard introduced with Day 13 (Albiriox): YAML frontmatter, `# <Title>`, `## TL;DR`, `## Attribution and confidence`, `## Kill chain — summary table`, `![kill chain SVG]`, `## Stage-by-stage detail`, `## RE notes` (when applicable), `## Detection strategy` with three sub-sections, `## Incident response playbook` with five sub-sections, `## IOCs`, `## Secondary findings`, `## Pedagogical anchors`, `## What's in this folder`, `## Sources`.
- Days 1-12 were rewritten from their pre-standard, shorter forms. Days 13-15 (already conformant) were left in place.
- Every day folder now ships a `kill_chain.svg` at the folder root (not in a `diagrams/` subfolder) with the GitHub-friendly `prefers-color-scheme` adaptive palette, accessibility metadata (`role="img"`, `<title>`, `<desc>`), numbered stage badges, MITRE tags, IOC anchors, attacker C2 cluster panel and bottom detection-anchors box.
- The day folders for `2026-04-29_ShaiHulud-Bitwarden`, `2026-04-30_FIRESTARTER-LINE-VIPER-UAT4356`, `2026-05-01_VECT-2.0-RaaS`, `2026-05-02_Nexcorium-TBK-DVR-CVE-2024-3721`, `2026-05-03_BAUXITE-CyberAvengers-AA26-097A`, `2026-05-04_C0063-Poland-Wiper`, `2026-05-05_Akira-SonicWall-CVE-2024-40766`, `2026-05-06_CodeOfConduct-AiTM-Storm-1747`, `2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada` and `2026-05-07_QLNX-Quasar-Linux-RAT` received a brand new `kill_chain.svg`.

### Rationale
- The Day 13 structural standard is the published norm; the older write-ups predated it and gave a GitHub reader a fragmented experience. The retrospective brings every day to the same readable, self-contained, defensible level.
- All Sigma / KQL / YARA / Suricata rule files, hunts and `iocs.csv` files were left untouched — the rule logic was not the deficit; the surrounding write-up was.

### Notes
- Legacy `days/*/spl/` folders remain physically present in the working tree on the Windows / WSL mount; they were untracked from git on 2026.05.11 (commit `7b2f3d6`) and can be physically removed from PowerShell with `Remove-Item days\*\spl -Recurse -Force` after a fresh `git pull`. Per the 2026-05-11 SPL retirement, the README, CHANGELOG and validators no longer reference SPL.

---

## 2026.05.11 — Maintenance — Drop Splunk SPL from the repo scope

### Removed
- All 15 `days/*/spl/*.spl` files (untracked via `git rm --cached`), covering every case from Day 1 (TheGentlemen + SystemBC) through Day 15 (UAT-8302). Going forward, daily lessons ship Sigma + KQL + YARA + Suricata only; Splunk users can still run the Sigma rules through `sigma convert -t splunk` on their side.
- SPL validator and dispatch entries from `tools/validate_all.py`.
- Sigma → Splunk conversion smoke test from `tools/lint_all.sh` and `tools/lint_sigma.sh` (Defender XDR / Microsoft 365 Defender remains the supported conversion target).
- SPL row from every day's `Detection coverage` table and `What's in this folder` table in `days/*/README.md`.
- SPL section from `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/hunts/peak_h1_sideload_accessibility_banking.md`.
- SPL anchor line from `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/kill_chain.svg` and `days/2026-05-10_Mexico-Water-AI-Assisted-OT/kill_chain.svg`.
- Splunk-over-Nutanix-Pulse SPL query in `days/2026-05-05_Akira-SonicWall-CVE-2024-40766/hunts/peak_h1_h2_h3.md` rewritten as KQL over a Sentinel custom log table.
- SPL / Splunk badge, layout entries and validation table rows from the repo-root `README.md`.

### Rationale
- The author cannot test SPL rules end-to-end against a live Splunk instance, so the SPL files were accumulating unverified content that increased maintenance burden without payoff. Sigma + KQL stays the load-bearing detection track; Suricata + YARA keep their network and file roles.

---

## 2026.05.11 — Day 15 — UAT-8302 China-nexus government espionage with shared APT arsenal

### Added
- `days/2026-05-11_UAT-8302-China-Government-Espionage/` — Cisco Talos disclosure (published 5-May-2026, modified 7-May-2026) of UAT-8302, a China-nexus advanced persistent threat group targeting government entities in South America since late 2024 and in southeastern Europe in 2025. The hallmark of the cluster is the **promiscuous rotation of shared implants** previously linked to other China-nexus clusters: NetDraft (a .NET port of FinalDraft / SquidDoor used by Jewelbug / REF7707 / CL-STA-0049 / LongNosedGoblin), CloudSorcerer v3 (Kaspersky 2024), VSHELL fronted by SNOWLIGHT and the newly observed Rust-based **SNOWRUST** stagers (UNC5174 / UAT-6382 lineage, single-byte XOR key `0x99`), the SNAPPYBEE / DeedRAT + ZingDoor combo (Earth Estries), and the Draculoader shellcode loader. Hardened tradecraft markers include the camouflage path `C:\ProgramData\Microsoft\Microsoft\` with double `Microsoft` segment, scheduled-task persistence under `Microsoft\Windows\Maps\{GUID}` with literal task names `ReconLiteDebug` and `RunWhatPC`, and Microsoft Graph + OneDrive as a covert C2 channel that blends into normal M365 egress. UAT-8302 also deployed the open-source Hades HIDS / HIPS kernel driver as a primitive for selective EDR-event suppression.
- Sigma (3): DLL side-loading anchors for `mspdb60.dll` or `wininet.dll` loaded from `Temp`, `ProgramData\Microsoft\Microsoft\` or `Users\Public\`; schtasks /create with the UAT-8302 literal task names and fake `Microsoft\Windows\Maps\{GUID}` path; open-source recon and credential-extraction tooling (`gogo`, `httpx`, `naabu`, `dddd`, ADExplorer `-snapshot`, `adconnectdump.py`, `MobaXtermDecryptor`, `SharpGetUserLoginIPRP`).
- KQL (3): Defender XDR — non-browser, non-Office process beaconing `graph.microsoft.com` or `login.microsoftonline.com` from `ProgramData\Microsoft\Microsoft\` (NetDraft); `mspdb60.dll` or `wininet.dll` image_load events outside System32 / SysWOW64 / WinSxS; GitHub or GameSpot dead-drop fetch followed within 5 minutes by a derived public-IP connection (CloudSorcerer v3 dead-drop resolver).
- YARA (1, multi-rule): `UAT_8302_NetDraft_FringePorch_2026` (Fody/Costura embedded helper + Graph beacon strings + Plugin.Run); `UAT_8302_CloudSorcerer_v3_2026` (process-name branching `dpapimig.exe` / `spoolsv.exe` + named-pipe IPC + GitHub or GameSpot dead-drop); `UAT_8302_VSHELL_SNOWLIGHT_SNOWRUST_Stager_2026` (Rust runtime markers, LexiCrypt strings, `0x99` XOR byte-loop pattern).
- Suricata (1, 5 sids): TLS SNI anchors for `drivelivelime.com`, `msiidentity.com`, `update-kaspersky.workers.dev`; HTTP host + URI for `trafficmanagerupdate.com/index.php`; bulletproof subnet egress (sids 8110001-8110005).
- PEAK hunts (3): H1 — side-load triad living in `ProgramData\Microsoft\Microsoft\`; H2 — AD Connect dump tooling fingerprint outside the formal sync appliance; H3 — GitHub or GameSpot dead-drop resolver C2 channel.
- `iocs.csv` — 18 SHA-256 hashes (NetDraft, FringePorch, VSHELL, ZingDoor, Draculoader, OSS recon stack, SharpGetUserLoginIPRP), 5 C2 domains, 8 bulletproof IPs, NetDraft drop paths, the literal scheduled-task name strings, and two operator notes about the `0x99` XOR cross-cluster anchor and the Graph OAuth token revocation playbook.
- `kill_chain.svg` — adaptive light/dark palette diagram with two lanes (victim government enterprise vs attacker C2 / proxy fabric), nine numbered stages from initial access through long-term espionage, a dedicated C2 cluster on the right with all listed domains and IPs, and a detection-anchors box that maps to the rules in `sigma/`, `kql/`, `yara/`, `suricata/` and `spl/`.

### Pedagogy
- *Promiscuous toolchain sharing across China-nexus clusters means attribution lives at the operational level, not the toolchain level.* A cluster name like UAT-8302 carries weight even without a 1:1 alias to a public actor brand.
- *The double-`Microsoft\Microsoft\` camouflage path under `ProgramData` is a near-zero-FP anchor.* Combined with Graph API egress, it makes for a clean high-confidence detection.
- *Microsoft Graph + OneDrive as C2 is impossible to block at the network layer for any M365-enabled organization.* Defense has to move inward to "who inside the host is reading or writing Graph tokens".
- *Dead-drop resolution (GitHub raw, GameSpot profile) is a structural pattern, not a binary signature.* A public-blob fetch followed within minutes by a derived public-IP connection is rarely benign and worth a high-signal detection.
- *Open-source Simplified-Chinese tooling (`gogo`, `Stowaway`, `SharpGetUserLoginIPRP`, Hades HIDS framework) is a soft attribution signal that often correlates with China-nexus operations.*

### Secondary findings
- MuddyWater (Iran) "Dindoor" backdoor, based on the Deno JavaScript runtime, targeting a US bank, a Canadian non-profit and a software company. Activity ramped after Operation Epic Fury (ceasefire 5-May-2026). The Deno runtime is a tradecraft novelty for Iran-nexus operators.
- CISA KEV active reminders: CVE-2026-31431 ("Copy Fail") Linux kernel local privilege escalation with federal deadline 15-May-2026; CVE-2026-6973 Ivanti EPMM actively exploited; CVE-2026-0300 PAN-OS Captive Portal RCE first fix expected 13-May-2026.
- npm worm "CanisterSprawl" (TeamPCP) — self-propagating variant in the Shai-Hulud lineage targeting popular SDK packages. TeamPCP is the same e-crime cluster tracked across Bitwarden Shai-Hulud, Mini Shai-Hulud, VECT 2.0 alliance and SAP @cap-js.

---

## 2026.05.10 — Day 14 — AI-Assisted Compromise of a Mexican Water Utility (SADM Monterrey)

### Added
- `days/2026-05-10_Mexico-Water-AI-Assisted-OT/` — Dragos and Gambit Security analysis (published 6-8 May 2026) of an unattributed single operator who, between December 2025 and February 2026, compromised at least nine Mexican government bodies (SAT, INE, civil registries and several state and municipal entities) and delegated approximately 75% of remote command execution to two commercial LLMs: Anthropic Claude as primary technical executor and OpenAI GPT as analytical processor. During the IT compromise of Servicios de Agua y Drenaje de Monterrey, Claude autonomously identified a vNode SCADA/IIoT gateway, generated a tailored credential list and ran two automated password-spray rounds against the SPA. The OT environment was not breached, but the case is the first publicly documented artifact-grade evidence of an LLM compressing IT-to-OT pivot identification from days/weeks to hours.
- Sigma (2): internal POST burst from a non-engineering host to OT/SCADA management web ports (vNode, Ignition, Wonderware, Bachmann); Python interpreter with long command lines and high internal fan-out consistent with BACKUPOSINT-class tooling.
- KQL (2): Defender XDR — Python launcher with ≥50 internal connections to ≥4 distinct ports inside a 5-minute window; Sentinel-style — outbound TLS to LLM API endpoints (`api.anthropic.com`, `claude.ai`, `api.openai.com`, `chat.openai.com`) from server-tier or service-account context.
- YARA (1): `LLM_Built_OffSec_Framework_Python_Heuristic_2026` — heuristic with three string bands (self-name banner, AI-author marker, offensive-tradecraft function names) plus Python operational primitives, capped between 50 KB and 8 MB.
- Suricata (1): four sids — east-west burst of POSTs against OT management web ports (login and `/api/.../auth` variants) and server-tier egress to LLM API SNIs.
- PEAK hunt (1): H1 — AI-paced reconnaissance pivot, time-compressed transition from broad enumeration to credential-aware password spray inside a 60-minute window.
- `iocs.csv` — top indicators including the four LLM API hostnames, the BACKUPOSINT/APEX PREDATOR self-naming strings, the 75% AI-directed execution metric, the prompt-framing bypass tactic, the SADM victim attribution and the unattributed cluster status.
- `kill_chain.svg` — adaptive light/dark palette diagram with two lanes (victim IT/OT-adjacent vs LLM platform plus attacker C2), eight numbered stages, a dedicated LLM-platforms cluster on the right, and a detection-anchors box that maps directly to the rules in `sigma/`, `kql/`, `spl/`, `yara/`, `suricata/` and `hunts/`.

### Pedagogy
- *AI does not bring novel ICS/OT capability today, it brings time compression.* Defenders must re-cost detection and response SLAs assuming IT-to-OT pivot identification can land in the first hour of compromise.
- *LLM API egress is now actionable telemetry.* Server-tier or service-account-context outbound TLS to `api.anthropic.com` or `api.openai.com` is high-value signal and rarely benign.
- *Cross-tenant credential reuse becomes a containment-grade primitive when the operator is an LLM.* Org-wide secrets uniqueness moves from compliance ask to incident-response prerequisite.
- *Single-password administrative interfaces on industrial gateways must be removed from internal-routable space.* The vNode pattern is widespread across IIoT/SCADA platforms (Ignition, Wonderware, Bachmann) and an LLM operator finds them deterministically.
- *Tabletops should add the AI-assisted IT-to-OT scenario to the standard NIST 800-61 playbook.* The first exercise must answer how response posture changes when 75% of operator actions are LLM-issued in real time.

### Secondary findings
- DAEMON Tools supply-chain backdoor (Kaspersky Securelist, 6-May-2026): trojanised installers between 8-Apr-2026 and 6-May-2026 in versions 12.5.0.2421 to 12.5.0.2434; .NET information collector with multi-protocol C2; chinese-speaking artifacts; effective infections in Russia, Belarus and Thailand. Clean version 12.6.0.2445.
- CISA + ASD ACSC + Five-Eyes — *Careful Adoption of Agentic AI Services* (1-May-2026): first joint-agency guide on agentic-AI security risks. Recommends per-agent cryptographic identity, short-lived credentials, encryption agent-to-agent and folding agentic AI into existing zero-trust governance.
- Frenos Mythos Readiness Assessment (6-May-2026): first publicly available simulated penetration test framework explicitly designed against the Anthropic-Mythos-class autonomous-agent threat model. Cyber digital twin plus AI reasoning agent enumerating attack paths without touching OT production.

---

## 2026.05.09 — Day 13 — Albiriox Android MaaS RAT with AcVNC FLAG_SECURE bypass

### Added
- `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/` — Cleafy Labs technical write-up of a Russian-speaking MaaS Android banking RAT priced at USD 650-720 per month that targets 400+ banking, fintech and cryptocurrency wallet apps worldwide. The novel primitive is **AcVNC** (Accessibility-VNC): the malicious AccessibilityService walks the live UI as `AccessibilityNodeInfo` JSON and streams it to the operator, which **bypasses Android's `FLAG_SECURE`** because the flag protects the framebuffer and `MediaProjection` but not the accessibility node tree. Delivery used a fake Penny Market dropper in the DACH region; iteration through Q1-Q2 2026 has expanded geography.
- Sigma (2): AccessibilityService binding to a non-store, non-system sideloaded package; default SMS handler change to a non-allowlist package.
- KQL (2): Defender XDR Mobile — sideload + accessibility within 24h on a banking-app device; Notification Listener + READ_SMS coexistence on a non-stock package.
- YARA (1): `Albiriox_Android_Banking_RAT_2026` — DEX magic at offset 0 + AccessibilityService + dispatchGesture + AccessibilityNodeInfo + getBoundsInScreen + TYPE_APPLICATION_OVERLAY + AcVNC marker (or blackscreen command) + AppInfos class + 2-of-N target package strings, capped at 50 MB.
- MTD CIM-normalised correlation (Lookout / Zimperium / Workspace ONE Intelligence) across install + accessibility + admin grant + SMS handler change in a 24h window per package per device.
- Suricata (1): three sids — plain-TCP heartbeat shape (HWID + battery + AcVNC body anchors) from corporate mobile VLAN, in-stream `blackscreen:` operator command, and a heuristic empty-SNI TLS rule for AcVNC stream egress.
- PEAK hunts (2): H1 — sideload + AccessibilityService grant within 24h on a banking-app device; H2 — Notification Listener + `READ_SMS` coexistence on a non-stock package.
- `iocs.csv` — capability and string anchors (AcVNC marker, AppInfos class, blackscreen commands, Golden Crypt crypter name, JSONPacker dropper string, target packages including BBVA, Santander, Binance, Coinbase, MetaMask, Bitget, Trust Wallet, Phantom). SHA256 hashes and live C2 IPs sit behind the Cleafy paywall feed and are noted but not duplicated here.
- `kill_chain.svg` — single-page accessible diagram with adaptive light/dark palette, two lanes (victim host vs attacker C2), nine numbered stages and a detection-anchors box that maps directly to the rules in `sigma/`, `kql/`, `yara/` and `suricata/`.

### Pedagogy
- *`FLAG_SECURE` is not a panacea on Android.* It protects the framebuffer and `MediaProjection`, not the AccessibilityNodeInfo tree. Banking and wallet apps that rely on it must combine it with `setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO)` on sensitive views and with `Activity.setRecentsScreenshotEnabled(false)`.
- *Accessibility is the universal escalation primitive on Android.* Anatsa, BingoMod, Brokewell and Albiriox all converge on the same single user-facing toggle. Any policy that does not constrain Accessibility-service grants on managed devices is incomplete.
- *SMS-OTP, push-2FA without number matching, and TOTP that is visible in the foreground are all reachable from an Albiriox-owned device.* The only durable second factor on Android is FIDO2 / passkey bound to the secure element.
- *Detection is on the side-effects, not the binary.* Sideload + Accessibility bind + Notification Listener + Default SMS handler change on the same device within 24h is a high-signal precursor that survives Golden Crypt and DEX string encryption.
- *Crypto custody requires action before host remediation.* Once seed phrases may have been exfiltrated, on-chain funds must be moved to a clean wallet before the device is wiped.

### Structural milestone
- First entry under the **Day 13 README standard** (15 sections, fixed order, exact heading names) and the new mandatory `kill_chain.svg` next to the README. Both gates pass: language gate (no Spanish prose) and structural gate (all 15 headings present, SVG present and referenced from the README).

---

## 2026.05.08 — Day 12 — CloudZ RAT + Pheno plugin (Microsoft Phone Link OTP theft)

### Added
- `days/2026-05-08_CloudZ-RAT-Pheno-PhoneLink/` — Cisco Talos write-up (5-may-2026) of a campaign active since January 2026 that pairs a ConfuserEx-packed .NET RAT (`CloudZ`, compiled 2026-01-13) with a previously undocumented plugin (`Pheno`) that abuses the Microsoft `Microsoft.YourPhone_8wekyb3d8bbwe` UWP package on Windows 11. Pheno reads the local `PhoneExperiences-*.db` SQLite cache to harvest mirrored SMS bodies and OTP-bearing notifications without any compromise of the paired phone — a host-side bypass of SMS-based 2FA.
- Sigma (2): non-YourPhone process reading `PhoneExperiences-*.db`; AppData-resident parent creating a scheduled task (loader persistence chain).
- KQL (2): Defender XDR — Phone Link DB read joined with `*.hellohiall.workers.dev` or backend-IP egress within 30 minutes; Pastebin raw fetch combined with Workers or backend-IP egress on the same host.
- SPL (1): same-host correlation across Pastebin, Workers C2 and backend IP `185.196.10.136` over Sysmon EID 3 / EID 22.
- YARA (1): `CloudZ_Pheno_Heuristic_2026` — PE + ConfuserEx markers + Phone Link package strings + Workers FQDN + dynamic-IL emit primitives + embedded `Microsoft.Data.Sqlite`.
- Suricata (1): four sids — TLS SNI for `hellohiall.workers.dev`, DNS query for the same, IP egress to `185.196.10.136`, and HTTP GET to the seven Pastebin raw paths used as dead-drop config.
- PEAK hunt (1): H1 — Phone Link DB read followed by Workers / backend egress within 30 minutes on the same host.
- `iocs.csv` — five SHA256 hashes (Rust dropper, two .NET loader variants, CloudZ, Pheno), three Cloudflare Workers FQDNs, backend IP, seven Pastebin URLs and the `HELLOHIALL` operator handle.

### Pedagogy
- *SMS-based 2FA is no longer "what's on your phone".* Windows 11 Phone Link mirrors SMS into a SQLite file in user space — any user-context implant can read it. SIM swap is no longer the only route to OTP capture.
- *Detection is on the file-event side, not the binary side.* CloudZ uses dynamic IL emit at runtime, so on-disk method signatures are weak. The cheap, durable detection is "who reads the SQLite that is not the YourPhone package" and "who beacons to `*.hellohiall.workers.dev`".
- *Cloudflare Workers + Pastebin* is a low-cost-infra C2 fabric: defenders rarely block `*.workers.dev` outright, Pastebin is often allow-listed, and rotating hostnames does not require rebuilding the binary.
- *Recovery is not a password reset.* SMS-mirrored content captured during dwell remains valid for service-side use. Revoke device tokens, rotate every code that may have been mirrored, and migrate to FIDO2 / passkey before re-enabling identity.

---

## 2026.05.07 — Day 11 — EVM/DeFi npm typosquatting (`namikazesarada010206`)

### Added
- `days/2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada/` — Xygeni write-up (6-may-2026) of a six-package brand-adjacency squat campaign (`viem-core`, `viem-utils-core`, `hardhat-core-utils`, `evm-utils`, `foundry-utils`, `web3-utils-core`) targeting Ethereum / Solidity / Hardhat / Foundry / Brownie developers to steal wallet keystores, deployer keys, AWS / npm / SSH credentials and `.env*`. Activation is on `require()` (not `postinstall`) — `npm install --ignore-scripts` does *not* mitigate.
- Sigma (2): credential-read burst from `node`/`ts-node` PID; `node` outbound to literal IPv4 (incl. known C2 `76.13.37.80`).
- YARA (1): `EVMDeFi_NPM_Typosquat_Telemetry_2026` — known-hash rule plus heuristic anchors (env-var gate strings + AES-256-GCM creation + `NODE_TLS_REJECT_UNAUTHORIZED` + IPv4 literal + dev-secret paths).
- KQL (2): Defender XDR — credential burst on dev host with Hardhat/Foundry/Brownie tooling; Sentinel — first-seen IPv4 outbound from `node` (30-day baseline).
- SPL (1): correlation between `npm install` of any of the six IOC packages and a credential-read burst within 2 h on the same host.
- Suricata (1): three sids — known C2 IP, TLS handshake to public IPv4 with empty SNI from dev VLAN, HTTP POST `/ingest` with binary-body shape from dev VLAN.
- PEAK hunts (2): H1 — "Builder bait" credential burst from `node` on host with dev tooling; H2 — "IP-only egress from dev tooling" without SNI.
- `iocs.csv` — `76.13.37.80`, `telemetry.js` SHA-256 `71426e93cb6143052d5aeeca920850f8a0343c95bc65aab9a15145848cc5bff1`, all six tarball shasums, npm publisher `namikazesarada010206` and GitHub repo `harunosakura030303-maker/evmchain-config`.

### Pedagogy
- *Activation on `require()` instead of `postinstall`* is the operational pivot of the year — your `--ignore-scripts` policy buys you nothing here. Hunt the **child of `node` reading dev secrets**, not the install hook.
- *Brand-adjacency squat ≠ classic typosquat* — names are plausible suffixes (`-core`, `-utils`, `-utils-core`), not character flips. Watchlists need to model "supplemental package vs real library" patterns.
- The Day 10 (QLNX) and Day 11 (this) cases are **two ends of the same supply-chain kill chain** — QLNX is the upstream RAT that exfiltrates `~/.npmrc` to enable account take-over; this is the downstream typosquat that feeds the operator's wallet drainage.
- When `DEPLOYER_KEY` / `MNEMONIC` is exfiltrated, **first move funds on-chain** to fresh wallets — *then* clean the host. The atypical IR ordering reflects that the impact is off-host.

---

## 2026.05.07 — Day 10 — QLNX (Quasar Linux RAT)

### Added
- `days/2026-05-07_QLNX-Quasar-Linux-RAT/` — Trend Micro write-up (5-may-2026) of a previously undocumented Linux RAT (v1.4.1) that targets developer/DevOps endpoints to harvest registry tokens (npm, PyPI, GitHub, AWS, GCP, Azure, kube, Docker, Vault, SSH) — *the upstream cause of npm/PyPI supply-chain compromises*.
- Sigma (4): write to `/etc/ld.so.preload`; drop of `.so` under `/tmp` `/var/log/.ICE-unix`; gcc compiling `.so` at runtime; `QLNX_MANAGED` marker in newly created persistence files.
- KQL (4): Defender XDR for Linux — `DeviceFileEvents` on `/etc/ld.so.preload`; burst of >=3 dev-credential file reads in 60 s by a single process; `ip-api.com` recon from server tier; `/tmp/.X<DJB2>-lock` mutex.
- SPL (3): auditd watch on `/etc/ld.so.preload`; `QLNX_MANAGED` literal hunt over osquery file ingest; credential burst by single process.
- YARA (1): `QLNX_Quasar_Linux_RAT_2026` — multi-anchor heuristic (markers + master pw `O$$f$QtYJK` + lock path + version `1.4.1` + dev-credential file paths + ELF magic).
- Suricata (1): 4 sids — DNS / HTTP / TLS to `ip-api.com` from server tier + custom-TCP beacon shape with `QLNX` + `1.4.1` markers.
- PEAK hunt: H1 — credential-burst + geo-recon correlation on developer/DevOps host.
- `iocs.csv` — file paths, markers, master password, mutex, version, family.

### Pedagogy
- T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking) and T1556.003 (Modify Authentication Process: PAM) — primary persistence vectors.
- Why "find the implant" hunts must anchor on **side-effects** (credential reads, ld.so.preload writes, gcc-on-host) rather than on signed binaries — QLNX runs in-memory and self-deletes.
- Re-image instead of clean: 7 persistence anchors + LD_PRELOAD respawn make on-disk eradication unsafe.

---

## 2026.05.06 — Day 9 — Code of Conduct AiTM (Storm-1747 / Tycoon2FA)

### Added
- `days/2026-05-06_CodeOfConduct-AiTM-Storm-1747/` — Microsoft Threat Intelligence campaign (4-may-2026): 35,000 users / 13,000 orgs / 26 countries / 92% US. PDF lure + Cloudflare CAPTCHA + reverse-proxy AiTM + device-add < 10 min for PRT persistence + inbox rules for BEC.
- Sigma (3): PDF lure on M365 EmailEvents; Entra ID device registration post sign-in; invisible-name InboxRule (BEC).
- KQL (3): AiTM kill-chain correlation (signin + device + inbox rule, 24h); first-seen attacker domain via PDF; PEAK H1 click-to-device hunt.
- SPL (1): InboxRule one-char/symbol-only name on Office 365 Management Activity.
- YARA (1): `CodeOfConduct_AiTM_PDF_Lure_2026` heuristic (PDF magic + URI Action + theme keywords + cheap-TLD anchors).
- Suricata (1): TLS SNI + HTTP Host signatures for known landing domains (`acceptable-use-policy-calendly[.]de`, `compliance-protectionoutlook[.]de`) plus heuristic for keyword-in-cheap-TLD.
- PEAK hunt write-up: H1 (click → device-add 2h window).
- `iocs.csv` — 2 attacker domains, 2 PDF filenames, lure keywords, Tycoon2FA TLD pattern, behavioral indicators, cluster identifiers.

### Pedagogy
- T1098.005 (Account Manipulation: Device Registration) — the persistence technique that survives password rotation.
- Why TOTP/SMS/push MFA do NOT mitigate AiTM, and why FIDO2/passkeys do.
- IR runbook emphasising `Remove-MgDevice` as the critical eradication step (not just password reset).

---

## Unreleased — drop CI workflows (2026-05-04, evening)

### Removed
- `.github/workflows/sigma-lint.yml`
- `.github/workflows/validate.yml`

Rationale: validation now runs locally before each commit via `tools/validate_all.py`,
`tools/lint_all.sh` and `tools/lint_sigma.sh`. The CI workflows added noise to the
repo (red ❌ badges on the commit history) without giving us anything we don't
already have on the laptop. If you want them back, both files are recoverable
from `git log --diff-filter=D -- .github/workflows/`.



## Unreleased — repo overhaul (2026.05.04)

### Added
- `tools/validate_all.py` — offline multi-format validator (Sigma, YARA, Suricata, KQL, SPL, CSV, YAML, Markdown links, Bash). PyYAML-only dependency.
- `tools/lint_all.sh` — wrapper that runs `validate_all.py` plus optional external tools: `sigma-cli`, `yara`, `suricata`, `actionlint`, `shellcheck`, `markdownlint`.
- `tools/sigma_check.py` — Sigma-only offline validator (also re-used by the offline path of `lint_sigma.sh`).
- `tools/generate_index.py` — regenerates `INDEX.md` and the auto-views from each day's YAML frontmatter. Tolerates filesystems that disallow unlink (Cowork / WSL bind-mounts) by falling back to merge mode.
- `.github/workflows/validate.yml` — full multi