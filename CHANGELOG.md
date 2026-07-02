# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 2026.07.03 — Day 67 — From Bing search to NTDS.dit: BumbleBee, AdaptixC2 and Akira

### Added
- `days/2026/07/2026-07-03_BumbleBee-AdaptixC2-Akira-SEO-to-NTDS/` — consolidated The DFIR Report x Swisscom B2B CSIRT analysis (published 2026-06-29) of a Bing SEO-poisoning intrusion set: a trojanized ManageEngine OpManager MSI DLL-sideloads BumbleBee (`consent.exe` loads `msimg32.dll`), which drops an AdaptixC2 beacon (renamed `wab.exe` / `AdgNsy.exe` injected via WMI); hands-on-keyboard NTDS.dit theft, Veeam DPAPI and LSASS dumping lead to ~77 GB exfiltration and Akira ransomware at ~44 h. Unattributed e-crime; underlying waves date to May/Jul 2025. Friday deep-dive #12 (DFIR Windows/AD) + #19/#24.
- Sigma (3): `bumblebee_consent_msimg32_sideload.yml` — consent.exe loading msimg32.dll from a non-System32 path (image_load); `adaptixc2_wab_masquerade_wmi_spawn.yml` — WmiPrvSE-spawned WAB.EXE masquerade from AppData; `ntds_wbadmin_veeam_psql_credtheft.yml` — wbadmin ntds.dit backup or Veeam psql credential dump.
- KQL (4): consent/msimg32 non-system image load; WMI-spawned WAB beacon; NTDS wbadmin + comsvcs LSASS + Veeam psql credential burst; Akira WMI shadow-copy delete + locker.exe flags.
- YARA (1 file, 3 rules): Akira Windows locker markers; Veeam DPAPI credential-dump PowerShell; SoftPerfect Network Scanner recon tool.
- Suricata (1 file, 9 sids): SEO-delivery domains, a BumbleBee DGA C2 domain, BumbleBee/AdaptixC2 C2 IPs and the reverse-SSH + SFTP exfil hosts — sids 9670001-9670009 (infra-decay).
- PEAK hunts (3): SEO MSI -> sideload -> DGA C2; WMI-spawned WAB masquerade beacon; NTDS/Veeam credential burst -> reverse SSH + FileZilla exfil.
- `iocs.csv` (55 entries) — 3 samples with SHA1/MD5, 13 BumbleBee DGA domains + delivery fronts, BumbleBee/AdaptixC2/exfil IPs, tradecraft command notes; a preserved source spelling discrepancy on one DGA domain. `kev.md` — 1/1 referenced CVE on CISA KEV (CVE-2024-40766, cited only for genealogy vs the SonicWall-Akira case).
- `kill_chain.svg` — template A, canonical palette, ransomware accent; victim AD-timeline lane vs operator delivery/tooling/impact lane with sideload, WMI-masquerade-beacon and credential-burst anchors.

### Pedagogy
- Detect the sideload, not the loader: a signed `consent.exe` loading `msimg32.dll` from `%TEMP%`/`%AppData%` is a hash-independent tell that fires at execution.
- A built-in launched by `WmiPrvSE.exe` from `%AppData%` with `OriginalFileName` intact (`WAB.EXE`) is a masquerade-plus-injection pattern that generalizes beyond AdaptixC2.
- `wbadmin` backing up `ntds.dit` off a DC is domain-database theft — treat it like `ntdsutil` or DCSync.
- NTDS exfiltration forces a double `krbtgt` rotation and full credential reset, not just re-imaging the encrypted servers.

## 2026.07.02 — Day 66 — Fulcio's blind spot: SSRF, JWKS cache poisoning and a Kubernetes token leak (CVE-2026-49478)

### Added
- `days/2026/07/2026-07-02_Fulcio-Sigstore-OIDC-SSRF-CVE-2026-49478/` — chained SSRF + JWKS cache-poisoning + Kubernetes ServiceAccount token leak in Sigstore Fulcio's OIDC discovery client (CVE-2026-49478, GHSA-f5mr-q85p-6hh6, disclosed 2026-06-30, fixed in Fulcio 1.8.6); no observed exploitation, vulnerability-exposure case.
- Sigma (3): `fulcio_oidc_discovery_crosshost_redirect.yml` — cross-host redirect during OIDC discovery; `fulcio_pod_egress_to_metadata_or_unexpected_host.yml` — Fulcio pod egress to cloud metadata/unexpected host; `fulcio_serviceaccount_token_external_use.yml` — Fulcio SA token used against a non-local target.
- KQL (4): egress to cloud metadata; jwks_uri host mismatch; SA token presented against a non-local API target; discovery redirect-chain anomaly.
- YARA (1 file, 2 rules): illustrative malicious OIDC discovery-document and PoC-script content heuristics (no compiled malware sample exists for this CVE class).
- Suricata (1 file, 5 sids): anomalous `.well-known/openid-configuration` fetches, redirect Location headers to `169.254.169.254`/RFC1918, generic Fulcio-egress-to-unexpected-host patterns.
- PEAK hunts (3): Fulcio egress to non-issuer hosts; Rekor anomalous-identity issuance; Fulcio ServiceAccount token used from an unexpected source.
- `iocs.csv` (17 entries) — vulnerability-exposure case, no campaign hashes. `kev.md` — 0/3 CVEs referenced in this case on CISA KEV.
- `kill_chain.svg` — template A, canonical palette, supply-chain accent, Fulcio/Kubernetes target lane vs attacker-operations lane with SSRF/JWKS-poisoning/token-leak anchors.

### Pedagogy
- A code-signing CA's OIDC discovery client is part of its trust boundary and must be threat-modeled like any other credentialed egress path.
- Blind SSRF is a primitive, not just recon: no reflected output does not mean no impact.
- Global credential-attachment on an HTTP transport (a token sent to every destination regardless of host) is a recurring anti-pattern, structurally similar to the Argo CD ServerSideDiff case's unconditional control bypass.
- Trust-root bugs are categorically worse than stolen-identity bugs: they require compromising no one, unlike the Mini-Shai-Hulud/Miasma npm-worm provenance-forgery cases in this repo.

## 2026.07.01 — Day 65 — Behind the console: AWS-console AiTM phishing kit (input_24)

### Added
- `days/2026/07/2026-07-01_AWS-Console-AiTM-input24-PhishingKit/` — targeted adversary-in-the-middle campaign (Datadog Security Labs, 2026-06-24) that cloned the AWS Management Console sign-in page and relayed MFA in real time; six NICENIC-registered, Cloudflare-fronted look-alikes (three AWS, three SendGrid) delivered via SendGrid/Nimbu to <50 US-based engineers. Kit gates rendering on a per-recipient encrypted `input_24` email blob; lineage ties to July-2025 crypto-wallet phishing and the PoisonSeeds kit (NVISO, Aug 2025).
- Sigma (3): `aws_console_aitm_dns_query.yml` — look-alike domain resolution; `aws_console_aitm_kit_endpoints_proxy.yml` — `input_24=`/`/api/*` request fingerprint; `aws_cloudtrail_consolelogin_after_aitm.yml` — ConsoleLogin Success correlation primitive.
- KQL (4): `endpoint_resolves_aitm_domain.kql` (Defender DeviceNetworkEvents); `inbound_lure_from_sendgrid_nimbu.kql` (EmailEvents+EmailUrlInfo); `aws_consolelogin_anomalous_source.kql` (Sentinel AWSCloudTrail, off-baseline ASN); `aws_post_login_key_and_user_creation.kql` (IAM persistence burst).
- YARA (1 file, 3 rules): input_24 kit JS, attacker validation `.bat`, PoisonSeeds SendGrid SPA.
- Suricata (1 file, 6 sids): DNS + TLS SNI + HTTP (`input_24=`, `/api/check`, `/api/auth`) — sids 9650001-9650006.
- PEAK hunts (3): H1 domain-hit -> ConsoleLogin correlation; H2 SendGrid/Nimbu lure with look-alike link; H3 post-login IAM persistence.
- `iocs.csv` (24 entries) — six phishing domains + kit endpoints/fingerprints + notes; coverage 2026-06-16..24. No CVE — no `kev.md`.
- `kill_chain.svg` — template A, canonical palette, identity-cloud accent; victim + operator lanes with DNS/`input_24`/ConsoleLogin detection anchors.

### Pedagogy
- MFA is not a login-legitimacy oracle: AiTM relays the live factor, so the signal is the session source (ASN/geo) and its provenance (a preceding look-alike-domain hit), not that MFA fired. FIDO2/passkeys break the class.
- Sender authentication is deliverability, not trust: SendGrid/Nimbu abuse passes SPF/DKIM/DMARC — gate on the URL destination host, not the envelope sender.
- Target-gated kits move detection off the page and onto the network: when the payload refuses to render for non-victims, DNS/proxy resolution and the `input_24`/`/api/*` fingerprint are the earliest reliable artifacts.
- Track the kit, not the domain: the input_24 gating flow persisted across wallet, Salesforce and AWS campaigns for a year while domains rotated behind Cloudflare.

## 2026.07.01 — Maintenance — Reconstruct missing Day 1 README (The Gentlemen RaaS + SystemBC)

### Fixed
- `days/2026/04/2026-04-28_TheGentlemen-SystemBC/README.md` — the folder's README was never committed, so `generate_index.py` and the Pages gallery silently skipped the case (orphan). Reconstructed a faithful 15-section README from the committed `kill_chain.svg`, `iocs.csv` and detection rules (Check Point Research, April 2026; SystemBC RC4 SOCKS5 + GPO weaponization). Passes the structural + language gates.
- Re-ran `generate_index.py` / `generate_site.py` / `generate_ioc_feed.py` / `generate_navigator.py`: case count 63 -> 64 across INDEX.md, gallery, and navigator per-case layers.
- Audit result: all 64 day folders now contain a README; the legacy `spl/` tombstone in this folder is retained intentionally (SPL retired 2026-05-11).

## 2026.06.30 — Day 64 — Dire Wolf: Golang Double-Extortion Ransomware

### Added
- `days/2026/06/2026-06-30_DireWolf-Golang-DoubleExtortion-Ransomware/` — Dire Wolf (DireWolf) double-extortion ransomware, a Go/UPX filecoder active since May 2025 and still posting victims in 2026 (Did Asia, automotive parts, Thailand, 2026-06-12); re-profiled by CYFIRMA on 2026-06-26. Technical analysis from Trustwave SpiderLabs, AhnLab ASEC and Protos Labs; Curve25519 + ChaCha20, intermittent encryption, `.direwolf` extension.
- Sigma (3): `direwolf_inhibit_recovery_burst.yml` — vssadmin/wbadmin/bcdedit recovery-denial; `direwolf_eventlog_kill_and_clear.yml` — WMI/taskkill eventlog loop + wevtutil cl; `direwolf_marker_and_note_fileevent.yml` — runfinish.exe marker + HowToRecoveryFiles.txt write.
- KQL (4): `direwolf_inhibit_recovery.kql`; `direwolf_eventlog_kill_loop.kql`; `direwolf_forced_reboot_selfdelete.kql`; `direwolf_marker_note_fileevents.kql`.
- YARA (1 file, 3 rules): `direwolf.yar` — host markers (mutex/marker/note/ext), recovery-command strings, ransom-note template.
- Suricata (1 file, 6 sids): `direwolf.rules` — tor-browser[.]io DNS/TLS/HTTP + onion-address string (infra-decay; durable detection is host-behavioral).
- PEAK hunts (3): recovery-inhibition burst; eventlog-kill loop; note/marker/forced-reboot co-occurrence.
- `iocs.csv` (27 entries) — 3 SHA256 + 5 MD5 (AhnLab + CYFIRMA), mutex, marker path, note, extension, onion + tor-browser[.]io infra, command/TTP notes. No CVE — no `kev.md`.
- `kill_chain.svg` — template A, canonical palette, ransomware accent; victim lane (guardrail -> kill services -> inhibit recovery -> log destruction -> encryption -> reboot/self-delete) and operator lane (build, kill lists, command set, extortion, infra, attribution).

### Pedagogy
- Recovery inhibition (vssadmin/wbadmin/bcdedit from one parent) fires before the `.direwolf` rename — the earliest reliable behavioral tell.
- A WMI-driven eventlog-kill loop can suppress 1102/104; scope from SIEM-forwarded command lines, not host logs.
- Forced reboot + sleep-then-`del` self-delete erases the sample post-encryption; preserve memory and the marker/notes on any host caught pre-reboot.
- Sound crypto makes recovery a backups problem — and the backups must survive the Veeam/Veritas kill-list and shadow-copy deletion (offline/immutable).

## 2026.06.29 — Day 63 — CL-STA-1062 / TinyRCT: A Chinese-Speaking APT's Custom .NET Backdoor Against Southeast Asian Government and Energy

### Added
- `days/2026/06/2026-06-29_CL-STA-1062-TinyRCT-Backdoor-SEA-Espionage/` — Palo Alto Networks Unit 42 (2026-06-26) detailed CL-STA-1062, a Chinese-speaking espionage cluster (overlaps Cisco Talos UAT-7237) active across East Asia since March 2022 that from mid-2025 targeted Southeast Asian government and state-owned energy, breaching >=10 orgs Oct-Dec 2025. The operator lives off open-source tooling (SoftEther VPN, VNT, Yuze, Mimikatz, JuicyPotato, fscan — renamed vmtools.exe/vmwared.exe/XDRAgent.exe) and adds a bespoke .NET backdoor, TinyRCT (`PerfWatson2.exe`), delivered via AppDomainManager injection. Monday Espionage rotation → primary slot #1 (APT state-nation, China). Secondaries: #19 malware RE (TinyRCT static behavior), #24 CTI tradecraft (UAT-7237 genealogy / living-off-open-source attribution cover).
- Sigma (3): `tinyrct_appdomainmanager_injection.yml` — `*AppDomainManager.dll` loaded from a user-writable path into a non-VS/non-Program-Files process; `tinyrct_perfwatson_masquerade_localappdata.yml` — `PerfWatson2.exe` executing from AppData; `tinyrct_choice_selfdelete.yml` — choice.exe timer chained with `del *.exe`.
- KQL (4): `tinyrct_appdomainmanager_dll_load.kql`, `tinyrct_perfwatson_appdata_exec.kql`, `tinyrct_choice_selfdelete.kql`, `tinyrct_persistence_and_c2.kql` — Defender XDR coverage of the sideload, the AppData masquerade, the self-delete chain, and the GoogleUpdaterTaskSystem persistence + staging/C2 beacon.
- YARA (1 file, 3 rules): `tinyrct_cl_sta_1062.yar` — TinyRCT backdoor (AES key + masquerade name), the AppDomainManager loader DLL, and the malicious .NET app-config.
- Suricata (1 file, 6 sids): `tinyrct_cl_sta_1062.rules` (2026630001-2026630006) — C2/staging IP contact, TinyRCT GET poll / POST exfil, PerfWatson2.exe + chrome_setup.zip retrieval.
- PEAK hunts (3): AppDomainManager sideload (H1), PerfWatson2.exe from the wrong location (H2), renamed tunnelers disguised as VMware/XDR (H3).
- `iocs.csv` (24 entries) — 6 SHA256 (backdoor, loader, dropper, SoftEther, VNT, fscan), C2 `45.32.113[.]172`, staging `139.180.134[.]221`, AES key, persistence task, masquerade names. No published CVE (ASPX web-shell initial access) → no `kev.md`.
- `kill_chain.svg` — template A, canonical palette + `acc-espionage` accent, victim Windows estate vs attacker infrastructure lanes, IOC anchors, verifier x2 PASS.

### Pedagogy
- Path beats hash for masquerade: genuine PerfWatson2 runs from Program Files, the backdoor from %LOCALAPPDATA% — anchor on execution location.
- A signed parent is not a safe parent: AppDomainManager injection runs attacker code inside a legitimately signed launcher.
- Environmental guards ("won't run outside Downloads/AppData") are both evasion and a high-fidelity hunt signature.
- No CVE is not no-risk: web-shell-first intrusions need web-app hardening + web-shell hunting, not a KEV entry to act.

## 2026.06.28 — Day 62 — RoboVPN / Neunative: A Free VPN That Ships a Residential-Proxy Botnet SDK (Vo1d/Popa backend)

### Added
- `days/2026/06/2026-06-28_RoboVPN-Neunative-Vo1d-Popa-Residential-Proxy-Botnet/` — Nokia Deepfield ERT (2026-06-18) reverse-engineered the free Windows VPN RoboVPN (Cyberkick Ltd.) and found a bundled residential-proxy SDK, Neunative, that turns the host into an exit node; the relay activates while the VPN is idle/disconnected and is stopped on connect, so traffic exits through the user's real residential IP. Same director (`gmslb[.]net`) and TLV protocol as the Vo1d/Popa Android-TV proxy botnet (XLab ~1.6M devices); proxy network publicly linked (Qurium/Synthient/Krebs) to NetNut / Alarum Technologies. Weekend auto-rescue → longest-gap primary slot #21 (DDoS / infra abuse — residential proxy networks; repo first). Secondaries: #7 supply chain (SDK shipped as a NuGet dependency), #19 malware RE (static RE of the native + .NET SDK).
- Sigma (3): `neunative_director_registration_useragent.yml` — director `/regdev` GET with UA `SDK` + `sdkv=`; `neunative_proxy_dll_load_and_registry.yml` — load of NeunativeWin/NG.dll; `proxyware_nonstandard_port6000_beacon.yml` — process beacon to non-standard TCP 6000 (non-X11).
- KQL (4): `neunative_director_registration.kql`, `neunative_dll_image_load.kql`, `proxyware_port6000_relay_beacon.kql`, `adb_loopback_5555_exposure.kql` — Defender XDR detection of enrollment, SDK DLL load, port-6000 relay fan-out, and ADB `0.0.0.0`/loopback:5555 exposure.
- YARA (1 file, 3 rules): `neunative_proxy_sdk.yar` — native SDK exports + director/registry markers, .NET shim DllImports, and host-artifact text detector.
- Suricata (1 file, 6 sids): `neunative_proxy.rules` (9620001-9620006) — director registration GET, UA `SDK`, relay TLS to known fronts on 6000, behavioral port-6000 threshold, director DNS, ADB 5555 reach.
- PEAK hunts (3): register-then-relay (H1), relay-active-while-VPN-idle (H2), ADB 5555 exit-node foothold (H3).
- `iocs.csv` (28 entries) — 5 SHA256, director `gmslb[.]net`, relay fronts `viki-play[.]com`/`star-layer[.]com`, port 6000/5555, registry/log/service host indicators, app infra, 3 decaying downstream loader IPs. No CVE (design/abuse + supply-chain case) → no `kev.md`.
- `kill_chain.svg` — template A, canonical palette + `acc-malware-re` accent, user-host vs operator-infrastructure lanes, verifier x2 PASS.

### Maintenance
- v11 SVG accent backfill committed (`tools/svg_accent.py` over ~62 existing `kill_chain.svg`); June `kev.md` set refreshed by the month-scoped KEV overlay; indexes/site/feeds/navigator regenerated cumulatively.

### Pedagogy
- A residential proxy network and a botnet differ only by consent — and the backend never checks it (same relay list for EULA- or malware-enrolled devices).
- Durable anchors are OS-independent behavior: director domain + relay on fixed non-standard port 6000; the ~360-host relay fleet rotates and IP blocklists age out.
- Inverted proxyware: "the VPN is off" is the relay's ON state — verify activation logic before declaring a sample clean, and run the sandbox past the 30-90 minute delay.
- Denylist destination filters fail by omission: `0.0.0.0/8` and port 5555 left open turn each exit node into an ADB-reachable foothold.

## 2026.06.27 — Day 61 — Lantronix EDS5000 BRIDGE:BREAK: Root Command Injection in a Serial-to-IP OT Bridge (CVE-2025-67038)

### Added
- `days/2026/06/2026-06-27_Lantronix-EDS5000-BRIDGEBREAK-CVE-2025-67038-OT-Bridge/` — CISA added CVE-2025-67038 (CVSS 9.8) to KEV on 2026-06-23 (FCEB due 2026-06-26) after Forescout-honeypot exploitation on 2026-04-05; unauthenticated OS command injection in the EDS5000 HTTP RPC failed-auth logging path (username concatenated into a shell command, runs as root). Weekend auto-rescue → longest-gap primary slot #10 (OT-IT bridge / energy — repo first). Secondaries: #15 edge appliances, #22 cyber-physical.
- Sigma (3): `eds5000_username_command_injection.yml` — webserver `username=`/`user=` query with shell metacharacters; `serial_device_server_anomalous_egress.yml` — firewall outbound from device-server net to non-internal dst; `eds5000_syslog_shell_after_authfail.yml` — syslog shell/downloader marker co-occurring with auth-failure.
- KQL (4): `eds5000_username_injection_proxy.kql`, `eds5000_shell_after_authfail_syslog.kql`, `eds5000_anomalous_egress.kql`, `serial_device_management_recon.kql` — Sentinel CommonSecurityLog/Syslog detection of injection, on-device shell, anomalous egress, and external recon.
- YARA (1 file, 2 rules): `eds5000_bridgebreak_exploit.yar` — captured-payload/PoC/honeypot text detectors for the injection signature and the BRIDGE:BREAK toolset.
- Suricata (1 file, 6 sids): `eds5000_bridgebreak.rules` (9610001-9610006) — URI + POST-body injection, root-shell output egress, second-stage fetch, Lantronix recon, Ubiquiti UniFi OS chain probe.
- PEAK hunts (3): exposure + exploitation attempts (H1), device-as-pivot egress (H2), cyber-physical sensor concealment (H3).
- `iocs.csv` (16 entries) — CVEs, exploitation markers, firmware baselines, behavioral anchors (no public C2 IP/hash; CVE/version/behavior-based).
- `kev.md` — 4/4 CVEs on CISA KEV (CVE-2025-67038 + Ubiquiti UniFi OS chain CVE-2026-34908/34909/34910), added 2026-06-23, due 2026-06-26.
- `kill_chain.svg` — template A, canonical palette, victim OT estate vs attacker operations, ICS (T08xx) impact lane, verifier x2 PASS.

### Pedagogy
- The IT/OT serial bridge is a man-in-the-middle on the sensor wire — root on it means lying to the historian about the physical world.
- With no host EDR on embedded Linux, syslog + network-behavior baselining are the telemetry; any device-server egress is high-signal.
- Concealment defeats log-based detection — only independent process-integrity reference catches manipulated sensor readings.
- A patch is a disclosure event: capable actors diff fixes and exploit before the write-up; reduce exposure first, then patch.

## 2026.06.26 — Day 60 — GentleKiller BYOVD Suite: Behavioral Detection Engineering Against Operator-Maintained EDR Killers

### Added
- `days/2026/06/2026-06-26_GentleKiller-BYOVD-Detection-Engineering/` — ESET Research (2026-06-18) exposed The Gentlemen RaaS operating 8+ in-house BYOVD EDR-killer variants (GentleKiller), three third-party killers (HexKiller/ThrottleBlood/HavocKiller), and affiliate Rust credential stealer OxideHarvest; Check Point (2026-05-04) leaked the 16.22 GB operator backend. Primary slot #25 (detection engineering): thesis — driver-hash IOC blocking fails against operator-maintained driver rotation; behavioral anchors survive. Secondaries: #19 RE, #3 RaaS.
- Sigma (3): `gentlemen_staging_dir_creation.yml` — file_event on GentlemenCollection path string, zero-FP pre-kill anchor; `byovd_driver_service_install.yml` — sc.exe kernel service create with .sys from %TEMP%/%PROGRAMDATA% non-standard path; `edr_process_mass_termination.yml` — taskkill.exe targeting named security processes (MsMpEng/CSFalconService/SentinelAgent/ekrn/etc.).
- KQL (4): `gentlemencollection_staging.kql` — DeviceFileEvents FolderPath/FileName has GentlemenCollection; `byovd_service_driver_creation.kql` — DeviceRegistryEvents ImagePath .sys in non-standard paths; `edr_process_termination_chain.kql` — 3+ security process terminations per host per minute threshold; `oxideharve_credential_harvester.kql` — buildx64*.exe by name or -i -u -p -t -o CLI pattern.
- YARA (1 file, 3 rules): `gentlekiller_oxideharve.yar` — GentleKiller_Process_Termination_Target_List (GentlemenCollection string + 3+ EDR names); GentleKiller_Impersonation_Layer (Enigma/Themida strings + vendor names); OxideHarvest_Rust_Credential_Stealer (Rust panic + chronium_browsers/gecko_browsers JSON + browser paths + CLI args).
- Suricata (1 file, 6 sids 9260001–9260006): OxideHarvest SMB burst login threshold; OxideHarvest HTTP credential dump POST; BYOVD driver .sys download via HTTP; FortiGate management path recon; SystemBC SOCKS5 beacon; OxideHarvest buildx64 filename download.
- PEAK hunts (3): H1 BYOVD pre-kill window — correlates driver service (non-std path) + EDR process termination within 10 min on same host; H2 GentlemenCollection staging — union of file/process/registry telemetry for zero-FP string; H3 EDR-silenced host — active hosts with zero process events + nonzero network activity (out-of-band, immune to EDR kill).
- `iocs.csv` (34 entries) — 25 SHA-1 hashes (8 GentleKiller variants × 2 packers, 3 third-party killers, 9 drivers, 2 OxideHarvest builds), GentlemenCollection staging path string, 3 behavioral note rows.
- `kill_chain.svg` — Template A (880×1280), canonical palette, 7 left victim stages (stages 3+4 stageK critical), 6 right operator ops boxes (box D opK critical), cross-lane arrowX at 3 points, SVG verifier ×2 PASS.

### Pedagogy
- Driver-hash IOC blocking is a losing arms race against BYOVD operators who rotate vulnerable drivers within days of PoC publication — behavioral detection (staging directory, service creation path, termination chain, host silence) is the only durable layer.
- GentlemenCollection directory string is a zero-FP behavioral anchor present in every observed Gentlemen intrusion regardless of variant — single file event match warrants IR escalation.
- Out-of-band EDR kill detection (H3): a host that stops sending process telemetry while still generating network traffic is a high-confidence BYOVD indicator detectable from the SIEM control plane even after host EDR is dead.
- Driver-rotation speed (new PoC to weaponized variant in days) demands proactive hunting over retrospective blocking — H1 correlates the last pre-kill telemetry window before encryption begins.

## 2026.06.25 — Day 59 — Miasma Dead-Drop C2 via GitHub API: codfish/semantic-release-action Tag Hijack

### Added
- `days/2026/06/2026-06-25_Miasma-Codfish-GHA-Tag-Hijack/` — Miasma toolkit operator (unattributed) force-pushed two orphan commits to `codfish/semantic-release-action` on 2026-06-24, repointing 16 floating tags (v2–v5) to a 781 KB obfuscated JS payload that polls the GitHub public commit search API for dead-drop marker `thebeautifulsnadsoftime` and `eval()`s returned command payloads — no traditional C2 infrastructure required. Primary sources: Aikido Security 2026-06-24; Microsoft Security Blog 2026-06-02 (Red Hat campaign). Slot #7 supply chain software (35-day gap, longest Thursday slot); connected to Miasma toolkit leaked Jun 10 2026 (Shai-Hulud/TeamPCP lineage).
- Sigma (3): `gha_bun_cleanup_action_exec.yml` — process_creation: Bun spawned from Actions runner parent with GITHUB_ACTION_PATH (high); `gha_composite_always_bun_run.yml` — file_event: composite action.yml with setup-bun + if-always + bun run GITHUB_ACTION_PATH co-occurrence (high); `github_api_commit_search_from_runner.yml` — network_connection: Bun/Node to api.github.com /search/commits (high).
- KQL (4): `defender_bun_runner_secret_dump.kql` — DeviceProcessEvents: Bun child of runner joined to credential env reads within 60s; `defender_gha_commit_search_api_c2.kql` — DeviceNetworkEvents: outbound to api.github.com/search/commits from Bun/Node with Miasma marker extraction; `sentinel_github_audit_tag_force_push.kql` — AuditLogs: force-push on refs/tags/ with floating major-version tag detection; `sentinel_npm_token_env_exfil.kql` — Syslog: 3+ distinct credential-class env reads in 60s from runner process.
- YARA (2 files, 5 rules): `miasma_dead_drop_js_marker.yar` — three rules for dead-drop markers (thebeautifulsnadsoftime, DontRevokeOrItGoesBoom, firedalazer/Hades); `miasma_composite_action_bun_pattern.yar` — two rules for malicious composite action.yml pattern and large obfuscated JS in action repo.
- Suricata (1 file, 6 sids 9000590–9000595): GitHub commit search API poll, TheBeautifulSandsOfTime marker, DontRevokeOrItGoesBoom marker, firedalazer Hades marker, oven-sh/setup-bun download, Miasma credential staging repo POST.
- PEAK hunts (3): `peak_h1_gha_tag_sha_mismatch.md` — tag-SHA ancestry check across all org workflows (scoping); `peak_h2_bun_outbound_ci_runner.md` — Bun process outbound from self-hosted runner (execution); `peak_h3_ci_credential_env_burst.md` — 3+ credential env var reads in 60s in runner context (credential access).
- `iocs.csv` (15 entries) — payload SHA256, 2 malicious commit SHAs, 3 dead-drop marker strings, dead-drop API URL, Bun action SHA, Miasma staging repo description, clean/affected tag notes.
- `kill_chain.svg` — template A (880×1280), canonical CSS-class palette, 6 victim stages + 6 attacker ops, bidirectional arrowX for dead-drop C2 channel; verifier ×2 PASS.

### Pedagogy
- Floating GitHub Actions tags (`@v2`, `@v3`) are mutable refs — pin to full 40-char commit SHA to make tag repoints ineffective.
- `if: always()` is a CI gating bypass: malicious composite steps with this condition run even when the legitimate step fails, ensuring payload execution regardless of CI outcome.
- Dead-drop C2 via legitimate APIs (GitHub commit search) bypasses all IP/domain egress blocklists; the only detection handle is behavioral — Bun/Node polling `/search/commits` from a runner process tree.
- Post-toolkit-leak, all downstream operators share the same marker strings — YARA/Sigma rules catch every Miasma variant regardless of operator identity.

## 2026.06.24 — Day 58 — SRG / Luna Moth Fast Flux DNS Infrastructure: Vishing-to-Extortion Against US Law Firms

### Added
- `days/2026/06/2026-06-24_SRG-LunaMoth-FastFlux-LawFirm-Extortion/` — Silent Ransom Group (Luna Moth / Chatty Spider / UNC3753) e-crime extortion operation targeting US law firms via vishing-to-RMM initial access, fast flux DNS evasion (ep6pheij[.]com, 22 ISPs / 18 countries, TTL ≤ 60s), bulk data exfil in < 30 min, and public leak-site extortion (business-data-leaks[.]com, 38+ firms posted); primary sources Resecurity 2026-06-08 and FBI IC3 Flash 260526; slot #29 DNS abuse (21-day gap, longest on Wednesday rotation).
- Sigma (3): `srg_rmm_spawned_by_office_or_browser.yml` — Office/browser parent spawning RMM installer from user-writable path (high); `srg_fast_flux_dns_ttl_anomaly.yml` — DNS query to known SRG fast flux domains (high); `srg_data_exfil_via_rmm.yml` — RMM process making large external connections (medium).
- KQL (4): `srg_rmm_install_from_browser.kql` — DeviceProcessEvents: RMM spawned by browser/Office; `srg_fast_flux_domain_lookup.kql` — DeviceNetworkEvents + Sentinel DnsEvents: known SRG domain hit; `srg_bulk_exfil_post_rmm.kql` — joined RMM-install + >100 MB outbound within 30 min; `srg_extortion_email_hunt.kql` — EmailEvents: inbound from business-data-leaks domain.
- YARA (2 files, 3 rules): `srg_fast_flux_domain_strings.yar` — domain string + DNS TTL byte patterns (2 rules); `srg_extortion_email_template.yar` — leak domain + extortion payment-language co-occurrence (1 rule).
- Suricata (1 file, 8 sids 9005800–9005807): DNS query / HTTP host / TLS SNI / DNS answer rules for ep6pheij.com, business-data-leaks.com, and spy-corporate infra-provider indicator.
- PEAK hunts (3): `peak_h1_fast_flux_dns_beacon.md` — known IOC query + behavioral fast flux (high IP rotation, high query cadence); `peak_h2_vishing_to_rmm_correlation.md` — RMM install from user path within 60 min of VoIP call; `peak_h3_rapid_exfil_after_rmm.md` — > 100 MB outbound from RMM process within 30 min of install.
- `iocs.csv` (15 entries) — 2 domains (ep6pheij[.]com, business-data-leaks[.]com), 4 RMM binary strings, 4 extortion language patterns, CVEs, USB variant note, and CISA/FBI source annotations.
- `kill_chain.svg` — template A (880×1280), canonical CSS-class palette, 7 victim stages + 6 attacker-infra ops, cross-lane arrowX annotations for RMM callback and exfil flow; verifier ×2 PASS.

### Pedagogy
- Fast flux DNS (TTL ≤ 60s, IP rotation across 22 ISPs) defeats IP-based blocklists — detection must target domain names and behavioral TTL anomaly, not destination IPs.
- Vishing-to-exfil completes in < 30 min: the only viable intervention is real-time detection of anomalous RMM parent process (browser/Office spawning installer) before the session consolidates.
- SRG is ransomware-free by design — no encryption, faster exfil, extortion via public leak site; victims cannot recover by restoring backups because the leverage is publication not encryption.
- Physical USB variant (Spring 2026) shows SRG willingness to operate in-person when remote vishing is blocked — physical-access controls and removable media policies are now part of the threat model.
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

## 2026.06.23 — Day 57 — Cloud Insider Recruitment: Underground SaaS Access Market

### Added
- `days/2026/06/2026-06-23_Cloud-Insider-Recruitment-Intel471/` — First primary for slot #20 insider threat. Intel 471 Cloud Insider Threat Report (Help Net Security 2026-06-11) documents three insider archetypes: negligent (stealer-harvested corporate credentials — Vidar #1 / Stealc_v2 #2 / ACR #3 in May-2026 top stealers), manipulated (AiTM Gold kit capturing post-MFA session tokens via Okta/Gmail proxy relayed to Telegram bot), and malicious (samsepi0l April 4 2026 auction of master-admin+Slack+Okta access; betway Salesforce bribe; Finduser POS access; 19/41 underground posts in 2025 actively recruiting). DeepStrike stat: 54%+ of ransomware victims found in stealer logs before the ransomware event.
- Sigma (3): `sigma_cloud_aitm_session_token_reuse.yml` — Azure SigninLogs successful MFA from non-corporate CIDR indicating AiTM token replay; `sigma_saas_bulk_download_after_offboarding.yml` — M365 Audit FileDownloaded/FileSyncDownloadedFull by offboarding-watchlist UPN; `sigma_infostealer_telegram_c2_process.yml` — Windows process_creation non-browser child spawning Telegram API beacon with ZIP creation in APPDATA/TEMP.
- KQL (4): `kql_aitm_token_replay_sentinel.kql` — Sentinel SigninLogs same UPN from 2 IPs within 300s of MFA success; `kql_bulk_saas_exfil_offboarding_xdr.kql` — XDR CloudAppEvents >=100 downloads in 60 min by flagged user; `kql_infostealer_telegram_beacon_xdr.kql` — XDR join non-browser Telegram HTTPS + ZIP creation within 5 min; `kql_permissions_creep_privileged_saas_access.kql` — Sentinel AuditLogs privileged Entra role with no activity >=30d.
- YARA (1 file, 3 rules): `yara_insider_threat_cloud.yar` — `VidarClass_Telegram_C2_Resolve` (PE with api.telegram.org + getUpdates/sendDocument + credential-dir strings); `AiTM_PhishKit_Okta_Google_Token_Harvest` (PHP kit targeting Okta/Google relaying tokens to Telegram); `CloudInsider_Stealer_Log_Archive_Pattern` (ZIP directory structure matching Vidar/Stealc harvest archives).
- Suricata (1 file, 7 sids 9570100-9570106): TLS SNI Telegram C2 (9570100); Mastodon C2 alternative channel (9570101); AiTM Telegram bot credential relay POST (9570102); Okta credential harvest POST (9570103); ZIP credential archive POST non-browser UA (9570104); bulk cloud storage large-response attachment (9570105); AiTM reverse-proxy X-Forwarded-For on Okta (9570106).
- PEAK hunts (3): H1 SaaS permission-creep inventory via Graph API + KQL (stale privileged Entra roles); H2 infostealer log corporate credential exposure (Intel 471/SpyCloud API + Sentinel watchlist join for exposed UPNs); H3 malicious insider recruitment correlation (HR watchlist + DeviceFileEvents/DeviceNetworkEvents data-staging indicators).
- `iocs.csv` (16 entries) — actor handles (samsepi0l, betway-insider, Finduser, Gold, Loadbaks), stealer families (Vidar, Stealc_v2, ACR/Acreed), targeted services, pipeline and structural notes.
- `kill_chain.svg` — Template A (880x1280), canonical palette, two-lane: victim path (credential harvest/AiTM phish → stealer log upload/token capture → underground IAB listing → recruited/manipulated insider → SaaS access + privilege escalation → bulk exfil → stager/ransomware handoff) + attacker infra (stealer dev Loadbaks, Telegram/Mastodon C2, underground markets, AiTM Gold kit server, IAB-to-affiliate pipeline). Verifier x2 PASS.

### Pedagogy
- Stealers are the ransomware early-warning signal, not just credential theft: DeepStrike's 54%+ pre-attack exposure in stealer logs means monitoring leaked corporate credentials in threat intel feeds is now a first-order ransomware prevention control.
- AiTM session token theft is invisible to the IdP: MFA registers as successful; detection requires cross-IP correlation on the same UPN within a tight time window post-MFA — not the authentication event itself.
- The insider threat triangle is stealer + recruiter + AiTM: defending one vertex without the others leaves the attack surface open; all three require separate detection hypotheses and different data sources.

## 2026.06.22 — Day 56 — ProSpy/BITTER: Hack-for-Hire Android Spyware Targeting MENA Civil Society Journalists

### Added
- `days/2026/06/2026-06-22_prospy-bitter-mena/` — First primary for slot #2 hack-for-hire/mercenaries. A BITTER APT-linked (T-APT-17, suspected India nexus) hack-for-hire operation has been running Android spyware ProSpy against Egyptian journalists, opposition politicians, and civil society in Egypt, Lebanon, Bahrain, UAE, and Saudi Arabia since at least 2022. Joint disclosure: Lookout + Access Now Digital Security Helpline, 2026-04-08; ESET ToSpy variant, 2025-10.
- Sigma (3): `prospy_c2_uri_pattern.yml` — HTTP POST to /v3/ C2 endpoint pattern; `prospy_c2_domain_lookup.yml` — DNS resolution of 7 known ProSpy C2 domains; `bitter_phishing_domain_pattern.yml` — BITTER digraph-pattern phishing infra detection.
- KQL (2): `prospy_c2_network.kql` — Defender XDR network events for known C2 domains and /v3/ URI; `prospy_staging_download.kql` — APK download from non-Play staging domains.
- YARA (1 file, 4 rules): `prospy_android.yar` — C2 endpoint strings, malicious package names, Kotlin worker class naming, C2 domain embeds.
- Suricata (1 file, 10 sids): TLS SNI match on 6 C2 domains; HTTP POST /v3/getType poll; /v3/ exfil endpoint pattern; botim-app.pro APK download; *.ai-ae.io staging pattern.
- PEAK hunts (3): H1 JARM+ASN 44901 pivot for proactive BITTER infrastructure discovery; H2 WorkManager periodic beacon detection in network flows; H3 CT log subdomain registration monitoring for BITTER domain pattern.
- `iocs.csv` (36 entries) — 7 C2 domains, 5 staging/distribution domains, 14 ProSpy SHA1 hashes, C2 URI strings, Kotlin worker class names, JARM fingerprint, ASN 44901 note.
- `kill_chain.svg` — Template A (880x1280), canonical palette, two-lane: victim path (spearphishing → APK delivery → WorkManager → collection → C2 beacon → exfil) + attacker infra (sockpuppets, phishing fleet, staging sites, C2 fleet, attribution chain, victimology). Verifier ×2 PASS.

### Pedagogy
- Hack-for-hire decouples operator from client: BITTER infrastructure is the technical fingerprint; who paid for the civil society targeting is not determinable from malware alone.
- iOS is not safe from resource-constrained targeted actors: iCloud AiTM + Signal QR device-link phishing succeeds where zero-click is unavailable; Apple Lockdown Mode does not block credential phishing.
- Infrastructure fingerprint (ASN + JARM) outlasts malware families: Dracarys→ProSpy evolution across 4+ years, same ASN 44901, same JARM — hunt the infra, not just the hash.
- Joint civil society + commercial research is the most effective mobile threat intel model: Access Now Helpline victim casework + Lookout RE + SMEX corroboration produced attribution impossible through any single channel.

## 2026.06.21 — Day 55 — Icarus SaaS Extortion via Klue OAuth: Salesforce CRM Data Theft

### Added
- `days/2026/06/2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion/` — Financially motivated extortion actor Icarus exploited a credential breach at Klue (competitive-intelligence SaaS) to steal OAuth refresh tokens, then replayed them against Salesforce REST API as NHI service accounts, bulk-exfiltrating CRM data from enterprise clients across technology, finance, healthcare, government, and education sectors; ReliaQuest 2026-06-17 / Huntress 2026-06-18 / BleepingComputer 2026-06-18; first primary for taxonomy slot #6 (SaaS abuse).
- Sigma (3): `salesforce_bulk_sobjects_enum_integration.yml` — proxy-layer detection of python-urllib UA hitting /sobjects enumeration endpoint; `saas_integration_oauth_refresh_anomaly.yml` — Salesforce Event Monitoring OauthToken refresh from non-vendor IP (high); `salesforce_api_burst_query_nhi.yml` — RestApiRequest /query burst from non-browser UA (push threshold to SIEM aggregation).
- KQL (4): `salesforce_api_exfiltration_hunt.kql` — DeviceNetworkEvents join on 4 Icarus C2 IPs + python-urllib pattern; `saas_integration_oauth_anomaly.kql` — CloudAppEvents NHI OAuth refresh volume anomaly; `icarus_extortion_email_session_id.kql` — EmailEvents for globalretailbrands.com.au sender + Session Messenger keywords; `cloudapp_bulk_api_query_nhi.kql` — Salesforce /query rate >200 per 30-min window.
- YARA (2 files, 3 rules): `icarus_extortion_note.yar` — extortion note detector (Session invite + alias + deadline + victim-class keywords); `salesforce_python_exfil_script.yar` — Python exfil automation fingerprint (python-urllib UA + sobjects + QueryMore pagination, three OR clusters).
- Suricata (1 file, 7 sids 9010005–9010011): C2 IP egress/ingress (×2); TLS SNI *.salesforce.com with JA4 placeholder; HTTP /sobjects + python-urllib UA; HTTP /query + python-urllib UA; QueryMore cursor pagination; SMTP extortion mail from globalretailbrands.com.au.
- PEAK hunts (3): `peak_h1_oauth_token_sprawl.md` — NHI accounts with >200 Salesforce /query per 30 min (SOQL + KQL); `peak_h2_salesforce_api_baseline_deviation.md` — OAuth refresh_token grant from IP outside vendor allowlist (SOQL EventLogFile + AADServicePrincipalSignInLogs); `peak_h3_saas_integration_inventory.md` — stale NHI OAuth grants >90 days scoped to high-value objects (Tooling API + ConnectedApplication SOQL).
- `iocs.csv` (15 entries) — 4 C2 IPs (high), python-urllib UA (medium), 2 Salesforce REST API endpoints (high), extortion alias "mr bean" (high), sender domain globalretailbrands.com.au (medium), QueryMore cursor string (medium), 5 contextual notes (Session Messenger infra, Klue IR scope, leak site post, prior OAuth-abuse actor lineage, Icarus maturity indicators).
- `kill_chain.svg` — Template A (880×1280), canonical CSS palette, 7 left stages / 6 right ops; stages 4 (sobjects enum) and 5 (bulk exfil) in stageK red; Op D (C2 IPs) in opK red; 3 cross-lane arrowX; SVG verifier ×2 PASS.

### Pedagogy
- OAuth refresh tokens issued to SaaS integrations are first-class credentials: they carry the same access as the authorizing user, persist indefinitely without rotation, and do not appear in human authentication logs.
- NHI (Non-Human Identity) lifecycle hygiene — inventory, scope audit, 90-day rotation — is the structural control; revocation after an incident is remediation, not prevention.
- The attack class (integration vendor breach → token theft → CRM exfil) has been executed by at least four distinct actors in 12 months (Icarus, UNC6395/Drift, ShinyHunters, Gainsight-class); the kill chain is durable, not actor-specific.
- Session Messenger as extortion C2 infrastructure mirrors ALPHV/BlackCat Signal usage: decentralized, no central abuse reporting path, complicates evidence preservation and takedown coordination.


## 2026.06.20 — Day 54 — Agentjacking via Sentry MCP DSN Injection

### Added
- `days/2026/06/2026-06-20_Agentjacking-Sentry-MCP-DSN-Injection/` — Tenet Security disclosed a novel attack class (2026-06-17) in which an attacker posts forged error events to any Sentry project whose public write-only DSN is discoverable via Censys or GitHub; AI coding agents (Claude Code, Cursor, Codex) with Sentry MCP integration fetch the event as trusted tool output, execute attacker-controlled `npx --yes @attacker/pkg`, harvest credentials (~/.aws, ~/.npmrc, ~/.docker/config.json, ~/.ssh/id_rsa, ~/.config/gh/hosts.yml), and exfiltrate via HTTPS — 85% agent execution rate across 100+ orgs; 2,388 exposed organizations identified; no CVE (Sentry classifies as architectural). First primary of slot #18 (AI/LLM threats); Saturday auto-rescue.
- Sigma (3): `sigma_npx_spawn_ai_agent_parent.yml` — npx/node spawned by AI agent processes with --yes/-y flags (process_creation, high); `sigma_cred_file_access_agent.yml` — node.exe reading credential files with AI agent parent (file_event, high); `sigma_sentry_dsn_public_exposure.yml` — Sentry DSN written to build output or env files (file_event, DLP/DFIR, low).
- KQL (2): `kql_npx_agent_spawn_xdr.kql` — Defender XDR DeviceProcessEvents + DeviceNetworkEvents, 7d lookback, 5-min beacon window post-npx; `kql_credential_file_read_agent.kql` — DeviceFileEvents correlating node credential reads with AI agent ancestor.
- YARA (1 file, 3 rules): `yara_agentjacking_npm_payload.yar` — rule 1: npm package with Resolution injection + npx auto-accept; rule 2: credential-path probe + HTTPS beacon in npm code; rule 3: Sentry ingest POST body with shell command in resolution field.
- Suricata (1 file, 4 sids): SID 9010001 Sentry ingest POST from developer subnet; SID 9010002 Resolution+npx pattern in ingest body; SID 9010003 advisory-tracker.com PoC beacon DNS; SID 9010004 node.js POST to non-registry endpoint.
- PEAK hunts (3): H1 npx agent beacon — execution hypothesis, DeviceProcessEvents+DeviceNetworkEvents; H2 credential file access — collection hypothesis, DeviceFileEvents; H3 Sentry DSN abuse — initial access hypothesis, Sentry Audit Log API + proxy/NGFW logs.
- `iocs.csv` (22 entries): advisory-tracker.com PoC beacon, Sentry ingest URL pattern, ## Resolution injection string, npx --yes/npx -y execution strings, X-Sentry-Auth header, DSN regex, credential paths, Agentjackstop mitigation tool, no-CVE note, 2388-orgs exposure count, 85% success rate, 71 Tranco-top-1M orgs, Authorized Intent Chain note, Claude Code version, secondary MCP supply chain references.
- `kill_chain.svg` — template A, canonical palette, 7 victim stages (DSN exposure → MCP fetch → prompt injection → npx execution [red] → credential harvest [red] → authorized intent chain → detection opportunity) + 6 attacker ops; verifier ×2 PASS (880×1280).

### Pedagogy
- Authorized Intent Chain: each step is individually legitimate; composite chain is a full credential-theft attack; traditional perimeter controls are blind to it.
- MCP trust model is the attack surface: tool output is treated as authoritative instruction; Sentry MCP has no output sanitization layer.
- Public write-only DSNs are injection points, not just privacy risks; rotate any DSN reachable from public repos or frontend bundles.
- Detection requires process-ancestry correlation (AI agent → node → npx → outbound HTTPS) not single-event alerting.



## 2026.06.19 — Day 53 — Iran-Nexus ATG Cyber-Physical Campaign: Fuel Monitor Manipulation via Internet-Exposed Veeder-Root Consoles

### Added
- `days/2026/06/2026-06-19_ATGFuelMonitor-IranNexus-CyberPhysical/` — Iran-nexus threat actors exploited authentication bypass, hardcoded default credentials (8-zero PIN), CVE-2025-58428 OS command injection (CVSS 9.4), and SQL injection on internet-exposed Veeder-Root TLD-350/TLS-450/TLS4B automatic tank gauge consoles (port 10001/tcp); CISA/FBI/NSA/DoE/EPA/DOT/TSA/USDA joint advisory IC3-260602 (June 2 2026); 1,061+ IPs globally exposed per Shadowserver (June 5 2026); physical-consequence: alarm suppression hides real fuel leaks, reading manipulation causes incorrect delivery operations. First primary of #22 (OT physical/cyber-physical).
- Sigma (3): `atg_port10001_external_inbound.yml` — inbound port 10001 from internet; `atg_os_command_injection_web.yml` — OS command injection in ATG web management proxy logs; `atg_unexpected_outbound_from_ot_host.yml` — outbound internet TCP from OT ATG subnet.
- KQL (3): `atg_port10001_internet_exposure.kql` — Defender XDR/Sentinel inbound port 10001 from external; `atg_config_change_command_exec.kql` — Syslog shell commands from ATG hosts; `atg_alert_suppression_hunt.kql` — CommonSecurityLog alarm disable/config change (Claroty/Nozomi CEF).
- YARA (1 file, 2 rules): `atg_exploit_patterns.yar` — ATG TLS protocol auth bypass probe and OS command injection payload strings; heuristic (no confirmed binary sample with public hash).
- Suricata (1 file, 5 sids): `atg_fuel_monitor_campaign.rules` — SID 2400001 port-10001 inbound; SID 2400002 default credential probe; SID 2400003 CGI OS cmdinj; SID 2400004 SQL injection; SID 2400005 OT device outbound C2/exfil.
- PEAK hunts (3): H1 internet exposure inventory; H2 auth anomaly and post-login config change; H3 physical consequence assessment (alarm suppression, dip-stick reconciliation, audit log gap).
- `iocs.csv` (15 entries): CVE-2025-58428, IC3-260602 advisory ref, port 10001/tcp, device models, EMA advisory, Shadowserver count, default credential strings, attack vectors, physical consequence notes, attribution, sectors, regulatory implications.
- `kill_chain.svg` — template A, canonical palette, 7 victim stages + 6 attacker ops; two critical red stages (alarm suppression, reading manipulation); cross-lane arrows; verifier ×2 PASS (880×1280).

### Pedagogy
- Network segmentation (no internet exposure on port 10001) eliminates auth bypass + hardcoded creds + cmdinj simultaneously — it is a stronger control than patching any single CVE.
- OT IR requires physical-site verification: after digital recovery, manual dip-stick must reconcile with ATG readings and all alarms must be tested against a simulated event before declaring safe.
- The "sensor lie" pattern (Stuxnet → FrostyGoop → ATG campaign) is the OT-specific attack class: attacker does not cause the physical event, only removes the operator's visibility into it.
- Default credential persistence across thousands of field-deployed ATG units is an installation-practice failure, not a zero-day — lifecycle credential management must extend to set-and-forget OT appliances.

## 2026.06.18 — Day 52 — Joomla JCE CVE-2026-48907: unauthenticated profile-import RCE sprayed by a botnet

### Added
- `days/2026/06/2026-06-18_JCE-CVE-2026-48907-Joomla-Unauth-RCE/` — pre-auth RCE (CVSS 10.0, improper access control) in JCE (Joomla Content Editor) by Widget Factory, the most installed Joomla editor. The `com_jce&task=profiles.import` endpoint is reachable unauthenticated and accepts any file/extension into the web-readable `tmp/` (`File::upload(..., $allow_unsafe=true)`), yielding a `*.xml.php` web shell in three requests. YesWeHack published root-cause + PoC 2026-06-12; exploit on GitHub 2026-06-09; CISA KEV 2026-06-16 (FCEB due 2026-06-19). Live botnet exploitation: a `profiles.import` POST then a `plugin.rpc&...&method=upload` POST dropping a shell (`m.php`) into `images/`/`media/`/`tmp/`. Fixed in 2.9.99.5 (2026-06-03), hardened 2.9.99.6 (2026-06-06). Thursday supply chain; primary #26 (AppSec/web exploitation). Secondaries #7 (parallel WordPress plugin supply-chain wave), #15 (LiteSpeed cPanel symlink-to-root CVE-2026-54420), #24 (PoC publication as mass-exploitation inflection point).
- Sigma (3): `jce_profiles_import_unauth.yml` — unauthenticated `profiles.import` POST (webserver); `jce_pluginrpc_upload_rce_marker.yml` — `plugin.rpc` upload carrying the `id=RCE` toolkit marker (webserver); `jce_php_dropped_under_webroot.yml` — `.php`/`.phtml`/`.php5` written under `tmp/`/`images/`/`media/` (file_event).
- KQL (4): `jce_php_dropped_webroot` executable PHP under Joomla media/tmp; `jce_webservice_shell_spawn` web account spawning shell/LOLBin; `jce_host_beacon_attacker_ips` traffic to/from known scanning IPs; `jce_import_chain_in_syslog` import->upload chain in forwarded web logs (Sentinel Syslog).
- YARA (1 file, 3 rules): rogue JCE profile XML (php/txt filetypes / `Pwned`), generic PHP request-sink web shell, and the `id=RCE` upload marker — all flagged as heuristics (no recovered hashed sample).
- Suricata (1 file, 7 sids): unauthenticated `profiles.import` POST, `plugin.rpc` upload with `id=RCE` marker, the broader file-browser upload, `.xml.php` body upload, web-shell access under media/tmp with `cmd=`, `python-requests` scanner UA, and the known-IP block (sample set).
- PEAK hunts (3): H1 unauthenticated profile import; H2 file-browser RPC upload chain + `id=RCE` marker; H3 PHP foothold under media/tmp + web-account shell.
- `iocs.csv` (25 entries) — CVE, the two endpoint URIs, the `id=RCE` marker (+ observed values), `.xml.php`, `m.php`/`/images/m.php`, rogue-profile `Pwned`, three scanning IPs, version-triage and timeline notes.
- `kill_chain.svg` — template A two-lane (victim Joomla host vs attacker/botnet infra), canonical palette, red anchors on the unauthenticated import, the file-browser upload and the web-shell drop.

### Pedagogy
- Three small weaknesses (missing authz, no extension check, `$allow_unsafe=true`) chain into one CVSS-10 pre-auth RCE; removing any one breaks the chain.
- A CSRF token is not authorization — public-page tokens are trivially harvested; authorization must be an explicit `authorise()` check.
- Web-writable directories must never execute code: deny PHP under `tmp/`/`images/`/`media/` and hunt for PHP where only media should live.
- Patching is not incident response — the update closes the entry point but leaves the shell, the rogue profile and any added admin; one vulnerable site means audit the whole portfolio.


## 2026.06.17 — Day 51 — Fake event-invitation phish kit: credential + OTP harvesting and RMM delivery

### Added
- `days/2026/06/2026-06-17_FakeInvitation-PhishKit-OTP-RMM/` — a high-volume, repeatable phishing kit (tracked by ANY.RUN, reported 2026-05-05; corroborated by GBHackers 2026-05-21) targeting US organizations with fake event invitations. One CAPTCHA-gated lure branches into (a) real-time harvesting of webmail credentials and the follow-up OTP, and (b) silent delivery of legitimate RMM tools (ScreenConnect, ITarian, Datto RMM, ConnectWise, LogMeIn Rescue) as a remote-access foothold. ~80 domains / ~160 links tracked (mostly `.de`, registered from Dec 2025); two backend flows — non-Google (`processmail.php` -> `process.php`) and Google (`pass.php`/`mlog.php` + Telegram relay `check_telegram_updates.php`). Wednesday identity & fraud; repo's first primary in slot #27 (BEC / email fraud). Secondaries #5 cloud/identity (OTP interception), #4 IAB (phishing-to-RMM foothold), #18 AI-assisted lure generation.
- Sigma (3): `rmm_screenconnect_unattended_from_userpath.yml` — ScreenConnect/ConnectWise client from a user/temp path with relay params (T1219, process_creation); `rmm_remote_support_applet_from_browser.yml` — LogMeIn/ITarian/Datto applet spawned by a browser from Downloads/Temp (T1219/T1204.002, process_creation); `dns_fake_invitation_phish_domains.yml` — DNS to the known lure domains (T1566.002, dns_query).
- KQL (4): `rmm_foothold_user_path_execution` RMM agent from a user-writable path; `phishkit_uri_signature_network` kit URI signature in `RemoteUrl`; `phishkit_lure_domain_contact` device contact with lure domains; `invitation_lure_email` inbound event-invitation lures with `.de` links (EmailEvents + EmailUrlInfo).
- YARA (1 file, 3 rules): saved kit pages — non-Google flow (`processmail.php`/`process.php`/`Incorrect Password`), Google flow (`pass.php`/`mlog.php`/`check_telegram_updates.php`), and the fixed `/Image/` brand-icon set — all flagged as page heuristics.
- Suricata (1 file, 7 sids): POSTs to `processmail.php`/`process.php`/`pass.php`/`mlog.php`, the `check_telegram_updates.php` beacon, the `/blocked.html` + `/Image/office360.png` fingerprint, and TLS SNI for the three known lure domains.
- PEAK hunts (3): H1 kit URI signature across the estate; H2 RMM agents outside the sanctioned baseline; H3 post-harvest account takeover + Telegram relay.
- `iocs.csv` (26 entries) — 6 static icon SHA-256s, 3 lure domains, the URI-endpoint set, and behavioural notes (request chain, CAPTCHA gate, RMM tools, re-prompt trick, TI hunt query).
- `kill_chain.svg` — template A two-lane (victim path vs operator/infrastructure), canonical palette, red anchors on OTP interception and the RMM foothold.

### Pedagogy
- Hunt the structure, not the domain: rotating `.de` domains are weak IOCs; the fixed request chain (`/favicon.ico` -> `/blocked.html` -> `/Image/*.png`), the icon SHA-256s and the PHP endpoints are durable across the campaign.
- A signed, sanctioned RMM tool is still a foothold when you did not install it — baseline approved remote-support tooling and alert on everything else (provenance over signature).
- Password reset != containment after OTP theft: revoke sessions/tokens and re-MFA, then move users to FIDO2 / passkeys.
- A CAPTCHA in front of a credential form is evasion (it filters sandboxes/crawlers), not assurance; the "Incorrect Password" re-prompt is a harvesting tell.


## 2026.06.16 — Day 50 — Qilin affiliate weaponises Check Point IKEv1 VPN auth-bypass (CVE-2026-50751)

### Added
- `days/2026/06/2026-06-16_Qilin-CheckPoint-IKEv1-CVE-2026-50751/` — a financially-motivated operator assessed by Check Point Research (medium confidence) to be a Qilin (Agenda) ransomware affiliate has exploited CVE-2026-50751, a CVSS 9.3 authentication bypass in the deprecated IKEv1 code of Check Point Remote Access VPN / Mobile Access / Spark Firewall, as the initial-access primitive for ransomware. In the wild since 2026-05-07; Check Point hotfixed (sk185033) and disclosed 2026-06-08, CISA KEV 2026-06-09, watchTowr published the root cause + a working bypass 2026-06-12. The flaw is client-controlled auth: a 4-byte bitmask parsed from the attacker's `VPNExtFeatures` IKE Vendor ID (magic `3cf187b2...eaf289f5`) is written to `state+0x4bc4` and bit `0x4` short-circuits `verify_peer_auth`, so a self-signed cert + a random signature is accepted; the attacker only needs a valid username and the ICA `O=` string (readable from the gateway's public TLS cert). Tuesday crime-economy; filed as Initial Access / ransomware-affiliate. Primary #4 IAB; secondaries #3 Qilin RaaS, #15 edge appliance, #24 CTI.
- Sigma (3): `qilin_recovery_inhibition.yml` — vssadmin/wmic/wbadmin/bcdedit recovery destruction (T1490, process_creation); `qilin_actor_vps_beacon.yml` — internal egress to the nine actor VPS IPs (T1071.001, network_connection); `qilin_linux_elf_staging.yml` — Linux exec of a freshly chmod'd ELF from a world-writable path (T1105, process_creation/linux).
- KQL (4): `checkpoint_vpn_bypass_logon_anomaly` Syslog audit for VID magic / `not a Check Point peer` -> `User saved` / actor IPs from 2026-05-07; `qilin_actor_vps_beacon` Defender XDR egress to actor IPs; `qilin_recovery_inhibition` recovery-destruction process events; `vpn_signin_from_actor_infra` Entra SigninLogs from actor IPs.
- YARA (1 file, 2 rules): `VPNExtFeatures` VID 16-byte magic for pcap/memory scanning; files embedding any of the nine actor C2 IPs — both flagged as heuristics (no public sample deep-dive yet).
- Suricata (1 file, 6 sids): VID magic over IKE UDP 500/4500 and TCP 443 Visitor Mode (TCPT), egress to and inbound IKE from the actor VPS IP set, and an ELF-fetch rule.
- PEAK hunts (3): H1 Check Point IKE log retro-hunt from 2026-05-07; H2 post-foothold Qilin staging/impact; H3 IKEv1 exposure + configuration hunt.
- `iocs.csv` (21 entries) — 2 CVEs, the VID magic + gateway log-string anchors, 9 actor VPS IPs, 2 published MD5 payload hashes, infra/comms notes.
- `kill_chain.svg` — template A two-lane (gateway/internal vs VPS/IKE bypass), canonical palette, red anchors on the auth bypass and the Qilin delivery.

### Pedagogy
- Never let the client decide how hard the client is checked: CVE-2026-50751 is CWE-1337 "mark your own homework"; a removed function parameter in the patch is the tell.
- A patch is not incident response: the bypass leaves a live VPN session and leaks the gateway internal IP + certificate — rotate creds and the ICA cert.
- Hunt the primitive, not the campaign: the `VPNExtFeatures` VID magic and the `not a Check Point peer` -> `User saved` log adjacency survive payload/infra rotation.
- "Deprecated" is a synonym for "still exploitable"; legacy IKEv1 moved to a new daemon (`iked`) but kept its flawed logic, and an edge VPN bug is a ransomware affiliate's cheapest valid account.


## 2026.06.15 — Day 49 — OceanLotus (APT32) SPECTRALVIPER via a FireAnt MetaKit supply-chain attack

### Added
- `days/2026/06/2026-06-15_OceanLotus-SPECTRALVIPER-FireAnt-SupplyChain/` — ESET's 11 June 2026 report on two 2024-2026 OceanLotus (APT32) campaigns deploying the SPECTRALVIPER backdoor and showing a shift toward domestic Vietnamese espionage: a supply-chain attack that compromised the FireAnt MetaKit update server (serving a malicious `setup.exe` over cleartext HTTP with no integrity validation, ~2025-10-02 to 2026-03-09) targeting stock investors, and a ~2024-11 to 2026-02 intrusion into a Vietnamese infrastructure/transport construction corporation (suspected MSSQL RCE). Both use DLL side-loading via a renamed signed binary (`IntelAudioService.exe`=`dtlupdate.exe`; `Toolbox.exe` copies) loading a SPECTRALVIPER loader DLL that injects into `OneDrive.Sync.Service.exe`, then an HTTPS beacon hiding encrypted host data in an HTTP Cookie header (`zd_cs_pm=`/`euconsent-v2=`). An OPSEC lapse exposed SPECTRALVIPER's internal `XGU` framework via RTTI. Monday espionage; repo's first OceanLotus/APT32 primary. Primary #1 APT state-nation; secondaries #7 supply chain, #19 malware-deep-dive (RE), #24 CTI tradecraft.
- Sigma (3): `spectralviper_signed_binary_sideload_launch.yml` — renamed signed side-loading host with the `/appmodel /StateRepository /Service` or `-uiDll` command line (T1574.002/T1036, process_creation); `spectralviper_loader_dll_sideload.yml` — `DtlCrashCatch.dll`/`SetupUi.dll` loaded from a user path (T1574.002, image_load); `spectralviper_injected_onedrive_beacon.yml` — `OneDrive.Sync.Service.exe` egress to non-Microsoft hosts (T1055/T1071.001, network_connection).
- KQL (4): `oceanlotus_spectralviper_c2` beacon to C2 domains/IPs and beacon URL; `oceanlotus_dll_sideload` loader DLL side-loaded from a user path; `oceanlotus_sideload_process` renamed signed side-loaders with distinctive command lines; `oceanlotus_fireant_supplychain` MetaKit update fetch from `metakit.fireant.vn` + child spawn.
- YARA (1 file, 3 rules): SPECTRALVIPER RTTI/framework strings (XGU::Pivot, ProcessReflector/Manager), Cookie-beacon shape (`zd_cs_pm=`/`euconsent-v2=` + beacon URL), and FireAnt downloader API (`V1/Update/GetUpdate`) — anchored on ESET-reported durable strings.
- Suricata (1 file, 6 sids): C2 domain TLS SNI + DNS, hardcoded beacon URL path, `Cookie: zd_cs_pm=`/`euconsent-v2=` prefix, FireAnt MetaKit update/download API, and staging/C2 server IPs.
- PEAK hunts (3): H1 renamed signed binary side-loading an unsigned loader DLL; H2 injected Microsoft process beaconing to non-Microsoft infrastructure; H3 third-party software updaters fetching insecure (cleartext/unsigned) updates.
- `iocs.csv` (52 entries) — 19 SHA-1 sample hashes, 6 C2 domains + compromised update host, 8 C2/staging IPs, beacon URL + update URLs, Cookie/RTTI/API string anchors, side-loading paths; ESET-sourced.
- `kill_chain.svg` — template A two-lane (victim/endpoint vs OceanLotus infrastructure), canonical palette, red anchors on the malicious update server and the signed-binary side-load.

### Pedagogy
- A legitimately-signed binary is an execution primitive: OceanLotus renames signed hosts and side-loads the malware — hunt the pairing (signed host + unsigned DLL from a user path), not signatures alone.
- Injecting into `OneDrive.Sync.Service.exe` buys cover; the durable tell is a benign Microsoft binary talking to non-Microsoft infrastructure.
- Beacons hide in plain sight: encrypted host data rode inside an HTTP Cookie header and the format survived across campaigns even as domains rotated.
- Update integrity is a supply-chain control: no signature validation + cleartext HTTP turned a market-data updater into a malware delivery channel.


## 2026.06.14 — Day 48 — Humanity Protocol $36M DPRK-linked bridge takeover via signer-laptop key theft

### Added
- `days/2026/06/2026-06-14_Humanity-Protocol-DPRK-Bridge-KeyTheft/` — Quantstamp's investigation (published via Humanity 12-13 June 2026) into the 8 June 2026 $36M Humanity Protocol ("Chinese Worldcoin") incident: a Bithumb-impersonation spear-phish to a director carried a malicious attachment whose remote-access loader was signed with a stolen/forged Korean Hancom code-signing certificate (a DPRK marker), gave remote-desktop control while evading EDR, and copied wallet data plus ~7 Gnosis Safe signer private keys from one laptop; those keys met the 3-of-6 (ETH) / 3-of-5 (BSC) threshold, so the attacker transferred Hyperlane bridge ProxyAdmin ownership, upgraded the proxy to a malicious unlimited-mint/drain implementation, moved ~141.18M $H on ETH and minted 200M+ on BSC, then dumped via Uniswap/PancakeSwap/Kyber over ~8h. Sunday weekend auto-rescue; repo's first crypto/DeFi (#16) primary and first Gnosis Safe / ProxyAdmin bridge-takeover case. Primary #16; secondaries #1 APT (DPRK), #19 malware-deep-dive (Hancom-signed loader), #24 CTI tradecraft.
- Sigma (3): `hancom_signed_binary_on_crypto_endpoint.yml` — Hancom-signer binary on a non-Korean-office endpoint (T1553.002/T1588.003, image_load); `wallet_keystore_access_by_nonwallet_process.yml` — keystore/seed access by a non-wallet process (T1552.001/T1555, file_event); `remote_access_tool_on_signer_endpoint.yml` — RAT/RMM spawned from an Office/mail client (T1219/T1204.002, process_creation).
- KQL (4): `humanity_bithumb_phish_email` Bithumb-impersonation with attachment to signers; `humanity_hancom_signed_loader` Hancom signer on an unexpected host; `humanity_wallet_keystore_access` keystore/seed access by non-wallet process; `humanity_rat_c2_beacon` remote-desktop/RAT egress from a signer endpoint.
- YARA (1 file, 2 rules): heuristic Hancom-signed loader and wallet/keystore-stealer string heuristics — explicitly behavioural, not a recovered-sample signature (no public hash released).
- Suricata (1 file, 5 sids): Bithumb look-alike host/landing-page markers and remote-desktop/RAT SNI (AnyDesk/RustDesk/TeamViewer) from a signer VLAN.
- PEAK hunts (3): H1 Hancom code-signing-cert anomaly on crypto endpoints; H2 keystore access during a remote-access session; H3 cross-domain correlation of a signer-endpoint alert to an on-chain ProxyAdmin/owner change.
- `iocs.csv` (14 entries) — Hancom cert subject, Bithumb pretext, reported exploiter ETH address (community-sourced), keystore/wallet paths, plus timeline/mechanics/attribution honesty notes; behavioural + on-chain coverage, no malware sample hash.
- `kill_chain.svg` — template A two-lane (victim/signer endpoint vs attacker on-chain), canonical palette, red anchors on the Hancom-signed loader and the ProxyAdmin ownership transfer.

### Pedagogy
- When the loss happens through valid signatures, there is no on-chain exploit to patch — defence lives on the signer endpoint and in key custody.
- A stolen code-signing certificate (Hancom on a crypto endpoint) is a durable, high-value IOC; signer subject is often the best field for catching DPRK loaders.
- Stolen private keys survive password resets — remediation is rotating Safe owners to hardware-isolated signers, not resetting the account.
- "Multiple keys on one laptop" turns a 3-of-6 multisig into a single point of failure; separation of duties is a technical control, not a slogan.


## 2026.06.13 — Day 47 — DevilNFC and NFCMultiPay locally-built Android NFC relay malware

### Added
- `days/2026/06/2026-06-13_DevilNFC-NFCMultiPay-NFC-Relay/` — Two previously-undocumented Android NFC relay families analysed by Cleafy TIR (pub 2026-05-18; DevilNFC recovered during a March-2026 Cleafy IR engagement): a socially-engineered victim taps their card on an infected phone, the contactless APDU stream is relayed live to a tapper at an ATM/POS, and the card PIN is harvested as a core step (extends fraud past contactless limits to chip-and-PIN / ATM). The story is attribution — a technique once monopolised by Chinese-speaking MaaS (SuperCard X) is now independently rebuilt by local actors: DevilNFC (Spanish, single dual-role APK on NFCGate, Xposed `findSelectAid()` AID-reroute, Kiosk lock) and NFCMultiPay (Brazilian, pure-Java reader, REST→MQTT broker with a retained `card_ready` PIN topic), both with AI-assisted-development tells; corroborated by ESET's NGate/HandyPay variant (2026-04-21). Saturday weekend auto-rescue; repo's first Mobile (#11) primary in 47 days. Primary #11; secondaries #18 AI/LLM, #24 CTI tradecraft, #26 AppSec/HCE.
- Sigma (3): `android_nfc_hce_service_sideloaded_pkg.yml` — HostApduService/NFC permission on a non-store sideloaded package (T1655.001); `android_kiosk_locktask_pin_overlay.yml` — Kiosk/lockTask + overlay PIN prompt by a non-MDM package (T1541/T1417.002); `android_sms_otp_forward_sideloaded_pkg.yml` — SMS/OTP read+forward by a sideloaded package (T1636.004/T1582). All `product: mtd`, `category: mobile_event`.
- KQL (3): `devilnfc_nfcmultipay_app_inventory` malicious package + NFC/SMS inventory; `devilnfc_c2_pin_exfil_network` DevilNFC C2 domains + `api_pin.php` + Telegram exfil; `nfcmultipay_mqtt_rest_relay` NFCMultiPay IPs + MQTT 1883 + `/api/nfc/*` REST.
- YARA (1 file, 3 rules): DevilNFC APK (dummy AID `F0010203040506` + `findSelectAid` + `libnfcgate.so` + KioskActivity), NFCMultiPay APK (MQTT `nfc/relay/` + REST `/api/nfc/*`), and a broad NFCGate-derived relay-core hunting rule (PPSE `2PAY.SYS.DDF01` + HCE meta).
- Suricata (1 file, 5 sids): DevilNFC C2 in TLS SNI (`nfcrackatm.com`, `spicynagets.shop`), `api_pin.php` POST exfil, NFCMultiPay `/api/nfc/poll` REST, MQTT relay to broker IPs (TCP 1883).
- PEAK hunts (3): H1 HCE-by-non-wallet sideloaded app inventory; H2 Kiosk + PIN-overlay + OTP-forward behavioural chain on one device; H3 relay-transport egress (MQTT 1883 / raw-TCP C2 / Telegram from a banking app).
- `iocs.csv` (27 entries) — 2 C2 domains, 2 broker IPs, 3 APK MD5s, package name, HCE dummy/PPSE AIDs, `libnfcgate.so`/`findSelectAid`/`KioskActivity`/`api_pin.php`, MQTT topics + REST endpoints, Protobuf relay opcodes; transport flagged as rotating, behaviour as the durable anchor set.
- `kill_chain.svg` — template A two-lane (victim phone vs operator infra + rooted tapper at POS/ATM), canonical palette, red anchors on the PIN-overlay capture and the HCE `findSelectAid()` AID-reroute.

### Pedagogy
- PIN harvest is the force-multiplier, not a footnote — it lifts a capped relay to ATM/chip-and-PIN; no legitimate app asks you to re-enter your card PIN to "verify".
- The manifest lies; the behaviour does not — DevilNFC declares one dummy AID and reroutes via a hook, so hunt on card-emulation by a non-wallet app, not on a static AID list.
- Transport rotates, primitives persist — raw-TCP/Protobuf vs REST→MQTT/1883 are interchangeable plumbing; anchor on HCE abuse, Kiosk, PIN overlay, OTP forwarding.
- Open-source (NFCGate) + uncensored local LLM = a new class of independent local malware developers; track capability diffusion, not just named actors. Issuer-side impossible-travel/device-binding is the real backstop.


## 2026.06.12 — Day 46 — LinkPro eBPF rootkit with magic-packet activation in a compromised AWS EKS environment

### Added
- `days/2026/06/2026-06-12_LinkPro-eBPF-Rootkit-MagicPacket-EKS/` — LinkPro is a Golang Linux backdoor found by Synacktiv CSIRT (2025-10-13) during DFIR on a compromised AWS EKS estate: an exposed Jenkins (CVE-2024-23897) led to a malicious Docker Hub image `kvlnt/vv` deployed across clusters, pod credential harvest, a vGet (Rust) downloader running vShell 4.9.3 in memory (UNC5174-linked tooling, unattributed here), and finally LinkPro installing two eBPF modules — a Hide module (Tracepoint/Kretprobe on `getdents`/`sys_bpf` to conceal files/PIDs/BPF objects) and a Knock module (XDP/TC magic packet: TCP SYN window 54321 → internal port 2233) — with an `/etc/ld.so.preload`→`libld.so` userspace fallback. Friday/Deep-dive; repo's first DFIR Linux/containers (#13) primary. Primary #13; secondaries #19 malware-RE, #7 software supply chain, #5 cloud/identity.
- Sigma (3): `linux_ldso_preload_rootkit_persistence.yml` — write to `/etc/ld.so.preload` or drop of `/etc/*libld.so` (T1574.006); `linux_container_serviceaccount_token_harvest.yml` — pod SA-token/cloud-cred file reads (T1552.001); `linux_ebpf_program_load_from_unexpected_binary.yml` — `bpf()` load from a non-allow-listed binary via auditd (T1562.001).
- KQL (4): `linkpro_ldpreload_and_hidden_artifacts` preload + hidden artifact file events; `linkpro_eks_pod_credential_harvest` pod token/cred reads; `linkpro_c2_vshell_vnt_network` C2 IP/domain + vnt relay 29872; `linkpro_ebpf_load_and_jenkins_cve_2024_23897` Syslog/auditd bpf load + Jenkins `@`-file-read recon.
- YARA (1 file, 4 rules): Go orchestrator, Hide eBPF module, Knock eBPF module, libld.so — anchored on durable module/string artifacts (per-intrusion rebuilds defeat hashes).
- Suricata (1 file, 4 sids): magic packet (TCP SYN window 54321), vnt relay (29872), vShell C2 IP, S3 staging URL `/wehn/rich.png`.
- PEAK hunts (3): H1 hidden-eBPF inventory discrepancy (bpftool vs auditd vs `prog_idr`); H2 `ld.so.preload` + `ss`-vs-`netstat` port 2233 seam; H3 magic-packet listener / non-CNI XDP-TC / vnt relay.
- `iocs.csv` (28 entries) — sample SHA-256 (orchestrators, Hide/Knock modules, libld.so, LKM, vGet), C2 IP/domains, S3 URL, Docker image, CVE-2024-23897, ports 2233/29872/window 54321, preload paths and hidden artifact names; behavioural anchors flagged as the durable set.
- `kill_chain.svg` — template A two-lane (victim AWS EKS estate vs operator infra + eBPF modules), canonical palette, red anchors on the eBPF Hide module load and the Knock magic-packet listener.

### Pedagogy
- eBPF is dual-use: the thing that watches the kernel can blind it — detect at `bpf()` load time and verify with RAM `prog_idr`, never trust post-infection `bpftool`.
- Hiding tools leave seams: `ss` (netlink) beats `netstat` (`/proc/net`), and a static-binary listing beats a `getdents` hook.
- Magic packets decouple firewall logs from reality (knock on 443 → host 2233); capture upstream on a tap because XDP_DROP hides the trigger.
- Behaviour outlives the build: LinkPro is recompiled per intrusion with per-host keys, so preload writes, hidden-artifact names, the magic-packet window and the eBPF module load are the durable anchors.

## 2026.06.11 — Day 45 — Argo CD ServerSideDiff Kubernetes Secret extraction (CVE-2026-42880)

### Added
- `days/2026/06/2026-06-11_ArgoCD-ServerSideDiff-CVE-2026-42880-K8s-Secret-Leak/` — Argo CD advisory GHSA-3v3m-wc6v-x4x3 (CVSS 9.6, published 2026-05-01 by `alexmt`, reporter `hoang-prod`; tracked as CVE-2026-42880) describes a missing authorization + data-masking gap: the `ServerSideDiff` gRPC/REST endpoint is the only Argo CD surface that does not call `hideSecretData()`, and when an Application carries `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` the `removeWebhookMutation()` backstop is skipped, so a user with the default `applications,get` RBAC coerces a server-side-apply dry-run (`argocd-controller` field manager) into returning real `etcd` Secret values — SA tokens, TLS keys, DB creds, API keys — in plaintext. A public Python PoC sweeps every managed Secret. Affected 3.2.0–3.3.8; fixed 3.3.9 / 3.2.11. Thursday/Supply-chain; repo's first GitOps/IaC (#31) primary. Primary #31; secondaries #7 software supply chain, #26 AppSec/web, #5 cloud/identity.
- Sigma (3): `argocd_serversidediff_secret_read.yml` — `ServerSideDiff` invoked by a non-admin subject (T1552.007, T1528); `argocd_application_includemutationwebhook_annotation.yml` — Application create/patch with the bypass annotation (T1190, K8s audit); `k8s_secret_ssa_dryrun_argocd_controller.yml` — `secrets` SSA dry-run by `argocd-controller` (T1552.007, K8s audit).
- KQL (4): `argocd_serversidediff_call_anomaly` rare-subject/fan-out baseline; `k8s_secret_dryrun_burst` cross-namespace dry-run burst; `argocd_includemutationwebhook_inventory` exposure inventory; `argocd_repo_creds_endpoint_access` companion CVE-2025-55190 endpoint hunt.
- YARA (1 file, 2 rules): content heuristics for the public PoC / derivative extractor script on disk (ServerSideDiff path + grpc-web framing; annotation/code-anchor/repo-creds indicators) — not compiled-sample signatures.
- Suricata (1 file, 4 sids): gRPC-web POST to the `ServerSideDiff` path; `managed-resources` enumeration; companion `/projects/{p}/detailed` repo-creds endpoint (CVE-2025-55190); requires decrypted L7 visibility.
- PEAK hunts (3): H1 `ServerSideDiff` caller baseline; H2 `IncludeMutationWebhook=true` exposure inventory; H3 K8s-audit `secrets` dry-run fan-out.
- `iocs.csv` (24 entries) — CVE IDs, advisory IDs, the vulnerable endpoint, the masking-bypass annotation, code anchors (`removeWebhookMutation`/`hideSecretData`), PoC content strings, affected/patched versions; no campaign hashes (exposure/PoC case).
- `kill_chain.svg` — template A two-lane (Argo CD/Kubernetes target plane vs attacker operations), canonical palette, red anchors on the masking-bypass annotation and the plaintext Secret leak.

### Pedagogy
- A "read-only" role is only as safe as the leakiest read endpoint it can reach — audit the output of read paths, not just the verb.
- Security controls toggled by annotations are time bombs; govern security-relevant annotations with admission policy (Kyverno/Gatekeeper), not free-text fields.
- Patching closes the read but does not un-leak Secrets already returned — rotation is the recovery step, and rotate repo creds too (CVE-2025-55190 shares the values).
- Detect the invariants the attacker cannot avoid: the `ServerSideDiff` method, the annotation, and the `argocd-controller` `secrets` dry-run in the K8s audit log.

## 2026.06.10 — Day 44 — Kali365 (K365) OAuth 2.0 device-code phishing-as-a-service

### Added
- `days/2026/06/2026-06-10_Kali365-K365-OAuth-DeviceCode-PhaaS/` — Arctic Wolf Labs (2026-06-02) tracked the Kali365/K365 PhaaS operator (first seen April 2026; FBI IC3 PSA260521, 2026-05-21) from its "Token Bingo" device-code abuse into a multi-brand operation: a live C2 panel (`panel.securehubcloud.com`, title "K365 Control"), a 126-host kit cluster active 6–27 May, and a MAX Messenger takeover branch. The kit abuses Microsoft's OAuth 2.0 device authorization grant — the operator app requests a device code, embeds the `user_code` in a OneDrive/SharePoint lure, and the victim authorizes it at the genuine `microsoft.com/devicelogin`, handing access+refresh tokens to the attacker and bypassing MFA (refresh valid up to 90 days, survives password reset). Wednesday/Identity-and-fraud; repo's first device-code-phishing and first dedicated PhaaS-infrastructure case. Primary #5 cloud/identity; secondaries #27 BEC, #6 SaaS, #24 CTI tradecraft.
- Sigma (3): `kali365_entra_device_code_signin_anchor.yml` — successful Entra sign-in via `deviceCode` protocol (T1528, T1078.004); `kali365_device_code_signin_from_hosting_asn.yml` — device-code sign-in from Cloudflare/hosting ASN; `kali365_c2_kit_network_connection.yml` — endpoint to `securehubcloud.com`/`attachedfile.com`/`greatness-marketing.top`/`mowell.tech` (T1071.001).
- KQL (4): `kali365_device_code_signin_anchor` device-code inventory+baseline; `kali365_device_code_then_token_use_new_asn` cross-ASN token reuse (T1550.001); `kali365_c2_kit_infra_beacon` endpoint beacon; `kali365_graph_mailbox_collection_post_devicecode` inbox-rule/mail-read/send after sign-in (T1114.002, BEC).
- YARA (1 file, 2 rules): device-code kit HTML template (loader string, C2 host, K365 Control, deviceauth) and MAX takeover page (Telegram exfil config, bot token, Russian prize/OTP strings) — content heuristics for HTML captures, not compiled samples.
- Suricata (1 file, 4 sids): TLS SNI to `securehubcloud.com` C2; DNS for `attachedfile.com` and `greatness-marketing.top`; kit loader string in HTTP response body.
- PEAK hunts (3): H1 device-code baseline/anomaly; H2 cross-ASN stolen-token reuse; H3 kit content/cert/banner fingerprint.
- `iocs.csv` (26 entries) — C2/kit domains, Cloudflare + Token Bingo IPs, TLS cert SHA1, banner/content fingerprints, SID, Telegram exfil bot/chat, abused legitimate Microsoft endpoints; Worker subdomains rotate so cert/banner/content are the durable anchors.
- `kill_chain.svg` — template A two-lane (victim identity plane vs operator infrastructure), canonical palette, red anchors on the MFA-bypass authorization at the genuine Microsoft endpoint and the 3-second C2 capture poll.

### Pedagogy
- MFA does not stop device-code phishing: the victim completes the challenge for the attacker; mitigate with Conditional Access on the device-code flow and FIDO2, not "turn on MFA."
- Revoke refresh tokens BEFORE resetting the password — the 90-day refresh token survives a reset; this is the most common token-theft IR mistake.
- A legitimate OAuth flow abused has no CVE and no binary; anchor detection on protocol rarity, cross-ASN reuse, and cert/banner/content fingerprints, not on rotating domains.

## 2026.06.09 — Day 43 — Kyber ransomware (dual ESXi + Windows backup/hypervisor encryptor)

### Added
- `days/2026/06/2026-06-09_Kyber-Dual-ESXi-Windows-Backup-Hypervisor-Ransomware/` — Rapid7 (Anna Sirokova, 2026-04-21) recovered two coordinated Kyber payloads from one March-2026 IR engagement: an ELF for Linux/VMware ESXi and a Rust PE (`win_encryptor 1.0`) for Windows, sharing a campaign ID and Tor infrastructure. The ESXi variant SSHes in, soft-kills VMs with `esxcli vm process kill`, defaces `/etc/motd` + the hostd docroot, and encrypts `/vmfs/volumes` with ChaCha8 + RSA-4096 (its "post-quantum Kyber1024" note is marketing); the Windows variant stops `veeam/vss/backup/sql/msexchange` services, runs an 11-command anti-recovery set (3-method VSS delete, `bcdedit recoveryenabled No`, `wbadmin`, `wevtutil cl`), optionally force-stops Hyper-V, and encrypts with AES-256-CTR + Kyber1024 -> `.#~~~`. Tuesday/Crime-economy; repo's first slot #30 (backup/DR/hypervisor ransomware) primary and first dual-OS encryptor side-by-side. Why-today is the slot gap + the acutely live backup-targeting theme (Veeam KB4852/CVE-2026-32996 2026-05-27; The Gentlemen leaked backup-kill playbook 2026-06-08), not a 24h incident.
- Sigma (3): `01_windows_recovery_inhibition_chain.yml` — VSS delete (WMI/wmic/vssadmin) + `bcdedit` + `wbadmin` (T1490, T1562.001); `02_windows_backup_service_stop_and_logclear.yml` — stop veeam/vss/backup/sql/msexchange + `wevtutil cl` (T1489, T1070.001); `03_esxi_esxcli_vm_kill_and_motd_deface.yml` — `esxcli vm process kill` + `/etc/motd`/hostd defacement (T1489, T1491.001).
- KQL (4): `k1_recovery_inhibition_commands` `DeviceProcessEvents` (11-command set, threshold-gated); `k2_backup_av_sql_service_stop` service-stop `DeviceProcessEvents`; `k3_hyperv_force_stop_and_maxmpxct` `Stop-VM -Force -TurnOff` + `MaxMpxCt` registry; `k4_esxi_syslog_esxcli_kill_deface` ESXi `Syslog`.
- YARA (1 file, 2 rules): ELF (ChaCha8/`esxcli`/`.xhsyw`/KYBER-CDTA-ATDC trailer) and PE (`win_encryptor`/`boomplay` mutex/`.#~~~`/recovery strings); string anchors supplement the behavioral rules.
- Suricata (1 file, 3 sids): SMB write of `READ_ME_NOW.txt`, `.#~~~` and `.xhsyw` extensions over SMB (lateral-encryption heuristics, tuning-dependent).
- PEAK hunts (3): H1 recovery-inhibition command burst; H2 backup/AV/SQL service stop pre-encryption; H3 ESXi `esxcli` kill burst + management-file defacement.
- `iocs.csv` (29 entries) — ELF/PE/old SHA-256, both extensions, ransom-note filenames, trailer markers, ESXi defacement paths, Tor onion addresses, behavioral command sets, `MaxMpxCt` regkey, plus Veeam CVE-2026-32996 and FortiGate CVE-2024-55591 as secondary context.
- `kill_chain.svg` — template A two-lane (ESXi/Linux encryptor vs Windows encryptor), canonical palette, red anchors on `esxcli` VM kill, ESXi defacement, and the Windows service-stop + recovery-inhibition set.

### Pedagogy
- The ransom note is marketing, not a spec: the ESXi ELF advertises Kyber1024 but runs ChaCha8 + RSA-4096 — verify crypto by decompilation, not by the criminal's claim.
- Specialization beats sophistication: native `esxcli`/`vssadmin`/`bcdedit`/`wbadmin`, no zero-day; measure threat by impact and reliability, not code novelty.
- Backups are the target — immutable/off-host/admin-plane-isolated backups are the control that survives slot #30; killing veeam/vss/backup/sql is the whole game.
- Detect the actions the attacker cannot avoid: per-build polymorphism beats hashes, but VM kill, 3-method VSS delete, recovery-disable, and log-clear are mandatory.


## 2026.06.08 — Day 42 — OP-512 China-linked IIS web shell framework (per-deployment crypto uniqueness)

### Added
- `days/2026/06/2026-06-08_OP-512-China-IIS-WebShell-Framework/` — ReliaQuest disclosed OP-512 on 2026-06-05 (moderate-high confidence China nexus), a custom three-shell IIS framework found on an internet-facing Windows Server 2016 / EOL .NET 4.0 host in a DMZ with a 75-day dwell. A `.aspx` file manager self-reports its own URL via a hex-encoded DNS subdomain (`a.<hex>.c.hcgos[.]com`, HTTP fallback to a Meterpreter C2); two `.ashx` handlers gate command execution behind a Base64->RC4->RSA-verify->execute pipeline with a per-handler RSA key. A shared builder randomizes identifiers and injects junk so identical logic hashes differently — signature detection is defeated by design. Fourth China-linked IIS cluster in a year (vs CL-STA-0048, GhostRedirector, DragonRank); Monday/Espionage, repo's first IIS web shell framework primary (slot #1).
- Sigma (3): `01_iis_worker_spawns_shell.yml` — `w3wp.exe` spawning cmd/powershell/whoami/LOLBin (T1505.003, T1059.003); `02_w3wp_hex_subdomain_dns.yml` — worker DNS with long hex-segmented subdomain or C2 apex (T1071.004); `03_iis_webshell_and_aspnet_temp_dll.yml` — `.aspx/.ashx` write to webroot or new DLL in ASP.NET temp dir (T1505.003, T1027).
- KQL (4): `k1_iis_worker_child_process` `DeviceProcessEvents`; `k2_w3wp_dns_c2_beacon` `DeviceNetworkEvents`; `k3_webshell_file_and_temp_dll` `DeviceFileEvents`; `k4_w3wp_reflective_imageload` `DeviceImageLoadEvents`.
- YARA (1 file, 2 rules): structural `.ashx` crypto-handler (RC4+RSA-verify+IHttpHandler+reflection) and `.aspx` self-report file manager — heuristic, not sample-bound (framework is polymorphic).
- Suricata (1 file, 3 sids): hex-subdomain DNS to `hcgos.com`; `python-requests` POST to `.aspx` upload path; Meterpreter C2 `43.160.202.246:8053`.
- PEAK hunts (3): H1 worker hex-DNS self-report; H2 worker shells + reflective .NET loads; H3 web shell write + ASP.NET temp DLL.
- `iocs.csv` (17 entries) — C2 domains/IPs, web shell interaction UA, plus behavioral/structural anchors and cluster genealogy; deployment-specific IOCs flagged as rotating.
- `kill_chain.svg` — template A two-lane (victim IIS/ASP.NET runtime vs attacker op), canonical palette, red anchors on the self-report beacon, the per-deployment polymorphism, the RSA-gated handlers and the in-memory escalation.

### Pedagogy
- A per-deployment-unique web shell defeats hashes by construction — anchor on structure (RC4+RSA-verify+IHttpHandler) and behavior, not bytes.
- A self-reporting shell turns every visit into a tripwire for the attacker; investigate suspected shells from logs, never browse the URL.
- Deleting the `.aspx/.ashx` is not eradication — compiled DLLs in `Temporary ASP.NET Files` outlive the source and reactivate.
- "Prevention fired" != "contained" on IIS: it restarts the worker and reloads memory tooling; isolate the host and fix the entry vector before closing.


## 2026.06.07 — Day 41 — Secure Boot 2011 certificate expiry (frozen-DBX bootkit exposure window)

### Added
- `days/2026/06/2026-06-07_SecureBoot-2011-Cert-Expiry-Bootkit-Exposure/` — On 2026-06-24 the Microsoft Corporation KEK CA 2011 expires (the Microsoft UEFI CA 2011 DB cert follows 2026-06-27, Windows Production PCA 2011 on 2026-10-19; dates per Microsoft's official table updated 2026-05-18); a device not migrated to the 2023 certificate family keeps its 2011 KEK forever and can never receive a new DB/DBX revocation, so its boot deny-list freezes. Eclypsium's 2026-06-02 operational analysis (alongside Microsoft "act now" guidance and NSA Dec-2025 UEFI guidance) spells out the consequence: every revoked-but-signed bootkit component (BlackLotus/CVE-2023-24932, BootHole/CVE-2020-10713, CVE-2024-7344, CVE-2025-3052, PKfail/CVE-2024-8105) succeeds on a frozen device because a DBX entry is the only field remediation. Posture/exposure case, no live victim; unattributed bootkit ecosystem; weekend auto-rescue; repo's first primary in slot #8 (supply chain HW/firmware).
- Sigma (3): `01_secureboot_optin_registry_tamper.yml` — Secureboot opt-in/state registry write by non-servicing parent (T1553.006); `02_esp_bootloader_replacement.yml` — EFI boot component write on a mounted ESP by a non-TrustedInstaller process (T1542.001); `03_bcdedit_mountvol_esp_tamper.yml` — bcdedit/mountvol/mokutil/bcdboot boot-policy LOLBin (T1542.003).
- KQL (4): `k1_secureboot_registry_change` Defender `DeviceRegistryEvents`; `k2_esp_boot_manager_write` `DeviceFileEvents`; `k3_boot_tamper_lolbin` `DeviceProcessEvents`; `k4_secureboot_posture_gap` `DeviceTvmSecureConfigurationAssessment` (frozen-state proxy).
- YARA (1 file): EFI bootkit / revoked-component string indicators (BlackLotus, CVE-2024-7344 reloader, gSecurity2 NULLing) — illustrative class detection, no fresh sample.
- Suricata (1 file): network staging of `.efi` payloads / BlackLotus-class self-delete patterns.
- PEAK hunts (3): H1 Secure Boot opt-in/state gaps; H2 ESP boot-component writes correlated with a mount; H3 boot tamper followed by HVCI/BitLocker going off.
- `iocs.csv` (24 entries) — expiring certificate names, Secureboot regkeys, ESP/boot paths, enabling CVEs; historical bootkit hashes labeled as class exemplars (not fresh).
- `kill_chain.svg` — template A two-lane (victim pre-OS trust chain vs attacker/ecosystem op), canonical palette, red anchors on the frozen KEK/DBX and the pre-OS code execution.

### Pedagogy
- The OS Secure Boot boolean is not integrity — ground truth is in the UEFI variables (PK/KEK/db/dbx) + PCR[7].
- Revocation (DBX), not patching, is the boot-layer remediation; cut the KEK and you cut the only field-remediation channel for the class.
- Sequence the migration: OEM firmware update before the OS certificate change, or a CMOS clear can strand the device.
- Below-the-OS implants invert the trust model: EDR runs above them, reimaging does not remove them — eradication is firmware re-flash.


## 2026.06.06 — Day 40 — OCPP EV-charging attack surface (ABB Terra AC heap overflow CVE-2025-5517 + OCPP WebSocket missing-auth class)

### Added
- `days/2026/06/2026-06-06_OCPP-EVCharging-ABB-TerraAC-CVE-2025-5517/` — SaiFlow's RE of the ABB Terra AC wallbox found CVE-2025-5517: an over-long OCPP `DataTransfer` `messageId` is `sprintf`-copied into a fixed buffer, overflowing the heap (CWE-122) and crashing the charger into an indefinite Denial-of-Charge (RCE assessed plausible); CISA published the advisory wave ~2026-05-26 (ICSA-26-146-01 / -141-05), the why-today. In parallel a 2026 cluster of CISA OCPP-backend advisories (EV.energy CVE-2026-27772, CVSS 9.4, CWE-306, ICSA-26-057-07; plus CloudCharge/EV2GO/Chargemap/Mobility46) shows the systemic flaw is missing authentication on the OCPP WebSocket — anyone who knows a station ID can impersonate a charger. Unattributed; weekend auto-rescue; repo's first primary in slot #33 (Automotive/EV).
- Sigma (3): `01_ocpp_cleartext_websocket_exposure.yml` — cleartext OCPP to a CSMS on 80/8080 (T1557 MITM precondition); `02_ocpp_websocket_upgrade_unauthenticated.yml` — OCPP-subprotocol WS upgrade to an OCPP path without Authorization (T1190, CWE-306); `03_csms_backend_shell_spawn.yml` — CSMS/OCPP backend spawning a shell or network tool (T1059).
- KQL (4): `k1_ocpp_cleartext_exposure` Defender `DeviceNetworkEvents`; `k2_ocpp_station_id_fanout` Sentinel `CommonSecurityLog`; `k3_ocpp_oversized_datatransfer_field` Sentinel `Syslog`; `k4_csms_backend_anomalous_child` Defender `DeviceProcessEvents`.
- YARA (1 file, 2 rules): oversized OCPP DataTransfer messageId/vendorId frame (BoF attempt, CVE-2025-5517); cleartext OCPP session indicators — both capture/memory heuristics, no public exploit binary exists.
- Suricata (1 file, 3 sids): cleartext OCPP WS upgrade; oversized OCPP DataTransfer messageId (CVE-2025-5517); OCPP upgrade without Authorization / station impersonation (2606001-2606003).
- PEAK hunts (3): H1 cleartext OCPP transport inventory; H2 OCPP station impersonation (CWE-306) via station-ID fan-out + unknown IDs; H3 charger crash/DoC correlated with oversized OCPP fields.
- `iocs.csv` (19 entries) — CVEs, OCPP message types/fields (DataTransfer/BootNotification/messageId), subprotocol markers, ports (80/443/8080), ABB affected/fixed version ranges, firmware header marker, behavioural anchors; no fixed network IOCs (vulnerability-class case, no sample).
- `kill_chain.svg` — template A two-lane (victim OCPP charger/CSMS plane vs attacker ops), canonical palette, red anchors on the firmware heap overflow and the backend missing-auth impersonation.

### Pedagogy
- An EV charger is internet-connected critical energy infrastructure; a fleet of them is grid-relevant (MadIoT load-swing class).
- Cleartext `ws://` is both the vulnerability multiplier (enables MITM injection) and the detection gift (makes every OCPP frame inspectable) — force `wss://`, instrument what is not yet.
- Embedded RTOS firmware (no ASLR/canaries, `sprintf`) is durable memory-corruption ground; vendor firmware signing caps the blast radius from RCE to DoS.
- TLS and endpoint authentication are different controls: TLS stops the MITM; it does nothing for an OCPP WebSocket that accepts any station ID (CWE-306). You need both.


## 2026.06.05 — Day 39 — Netlogon CVE-2026-41089 (unauthenticated 0-click RCE as SYSTEM on Windows domain controllers)

### Added
- `days/2026/06/2026-06-05_Netlogon-CVE-2026-41089-DC-RCE/` — Microsoft (WARP team) patched CVE-2026-41089 in the 2026-05-12 Patch Tuesday; Belgium's CCB confirmed active in-the-wild exploitation against domain controllers on 2026-05-29, with Orca/BleepingComputer/SecurityWeek/Help Net Security following 2026-06-01/02. A stack-based buffer overflow (CWE-121) in the Netlogon RPC (MS-NRPC) packet handler lets an unauthenticated attacker send one crafted request (TCP/135 dynamic RPC or `\PIPE\netlogon` over SMB 445) and execute code as SYSTEM on a DC — a domain-wide compromise. CVSS 9.8; all supported Windows Server incl. 2025; attacker unattributed; not yet in CISA KEV at time of writing. Repo's first primary in slot #12 (DFIR Windows/AD).
- Sigma (3): `01_netlogon_dc_anomalous_child_process.yml` — core service (lsass/services/svchost) spawning a shell/LOLBin on a DC (T1068); `02_netlogon_service_crash_restart.yml` — SCM 7031/7034 for Netlogon (T1210 overflow attempt); `03_dcsync_replication_nondc.yml` — Security 4662 replication-rights GUID from a non-DC principal (T1003.006).
- KQL (4): `k1_netlogon_dc_lsass_child` Defender `DeviceProcessEvents`; `k2_dcsync_4662_replication` Sentinel `SecurityEvent`; `k3_netlogon_service_crash` Sentinel `Event`; `k4_dc_inbound_rpc_anomaly` Defender `DeviceNetworkEvents`.
- YARA (1 file, 2 rules): follow-on (not exploit-specific) DCSync/Mimikatz command strings; Impacket secretsdump/DRSUAPI tool markers.
- Suricata (1 file, 3 sids): DRSUAPI DsGetNCChanges (DCSync wire), Netlogon RPC interface bind, `\netlogon` named pipe over SMB (4100501-4100503).
- PEAK hunts (3): H1 SYSTEM shell from a core service on a DC (≈0% FP); H2 DCSync from a non-DC principal since the patch date; H3 Netlogon crash correlated with new SYSTEM activity.
- `iocs.csv` (20 entries) — CVE, patch/exploitation dates, MS-NRPC + DRSUAPI interface UUIDs, replication property GUIDs, Event IDs (7031/7034, 4662, 1102), ports, behavioural anchors; no fixed network IOCs (memory-corruption RCE, no public sample).
- `kill_chain.svg` — template A two-lane (victim DC/AD plane vs attacker ops), canonical palette, red anchors on the stack overflow and the krbtgt/NTDS.dit access.

### Pedagogy
- RCE inside a trusted authentication service is a blast-radius problem: code execution in Netlogon = domain compromise, not host RCE.
- Detect the forced consequences (DCSync, golden tickets, log clears), not a sub-3-second exploit with no public sample.
- krbtgt must be double-rotated after any confirmed DC compromise; single rotation leaves forged golden tickets valid.
- Enhanced logging built for last year's Netlogon bug (Zerologon EID 5827-5831) does not detect a buffer overflow - match telemetry to the bug class.


## 2026.06.04 — Day 38 — Kirki CVE-2026-8206 (unauthenticated WordPress admin account takeover)

### Added
- `days/2026/06/2026-06-04_Kirki-CVE-2026-8206-WP-AccountTakeover/` — Wordfence/Defiant, Orca and SecurityWeek (2026-06-01/02) disclosed CVE-2026-8206 (CVSS 9.8, CWE-269) in the Kirki WordPress plugin: `CompLibFormHandler::handle_forgot_password` mails the password-reset link to an attacker-supplied email instead of the account's stored address, so one unauthenticated request with a known username + attacker email takes over any account including administrator. Affects Kirki 6.0.0–6.0.6 (fixed 6.0.7, 2026-05-18); ~150K of 500K+ sites vulnerable; early active scanning reported. Repo's first primary in slot #26 (AppSec/web exploitation).
- Sigma (3): `kirki_forgot_password_rest_abuse.yml` — webserver POST to a forgot-password route with an email= param (T1190); `wordpress_user_enumeration_rest_author.yml` — REST `/wp-json/wp/v2/users` + `?author=` enumeration precursor (T1087.001); `wp_webshell_php_drop_uploads.yml` — file_event PHP under `wp-content/uploads` (T1505.003).
- KQL (3): `wp_php_webshell_dropped_uploads` Defender `DeviceFileEvents` PHP in uploads; `wp_webservice_account_shell_spawn` `DeviceProcessEvents` web account spawning shell/LOLBin; `wp_host_outbound_rawcode_pull` `DeviceNetworkEvents` web host to raw-code/paste hosts.
- YARA (1 file, 2 rules): generic PHP eval-over-request-input web shell; injected WordPress admin/auth-bypass backdoor.
- Suricata (1 file, 3 sids): forgot-password exploit POST, WP REST user enumeration, PHP-under-uploads request (4100401-4100403).
- PEAK hunts (3): H1 reset-email recipient mismatch (≈0% FP); H2 new/altered admin after disclosure; H3 web-shell foothold on WordPress hosts.
- `iocs.csv` (15 entries) — CVE, vulnerable handler/source path, version range, behavioural anchors (reset-recipient mismatch, PHP under uploads, web-account shell spawn); no fixed network IOCs (logic bug).
- `kill_chain.svg` — template C single-lane timeline, canonical palette, two red anchors (reset link to attacker mailbox, PHP web shell under uploads).

### Pedagogy
- A logic bug has no signature: detect behaviour (reset recipient != stored email, PHP under uploads), not a payload hash.
- Patch-gap is a window: hunt from the 2026-05-18 patch date, not the 2026-06-02 disclosure date.
- Self-service reset/SSPR flows are privilege boundaries — bind the destination to the server-side record, never to client input.
- "No WAF alert" is not "not exploited": verify 9.8/PR:N CMS plugin bugs by artifact (admin diff, uploads scan).


## 2026.06.03 — Day 37 — ip6.arpa Reverse-DNS Phishing (wildcard A on IPv6 reverse zones)

### Added
- `days/2026/06/2026-06-03_ip6arpa-Reverse-DNS-Phishing/` — Infoblox (2026-02-26), BleepingComputer (2026-03-08) and CloudSEK (2026-03-25) documented a commodity phishing technique that abuses the `ip6.arpa` reverse-DNS namespace: the operator takes a free IPv6 `/48` from a tunnel broker (Hurricane Electric), delegates the matching reverse zone to a high-reputation CDN nameserver (Cloudflare), and sets a wildcard `A` record so every per-victim random subdomain resolves to a phishing IP, hidden in email as an image link. Identity-and-fraud slot #29 (DNS-as-attack-surface) — the repo's first primary in that slot.
- Sigma (3): `s1_dns_query_ip6arpa_text_prefix.yml` — Sysmon DNS query with a text label prefixed to an ip6.arpa nibble chain (T1566.002); `s2_proxy_http_to_ip6arpa_host.yml` — proxy request to a `.ip6.arpa` host (T1204.001); `s3_network_connection_ip6arpa.yml` — process connection to a resolved `.ip6.arpa` host.
- KQL (3): `k1` Defender `DeviceNetworkEvents` `.ip6.arpa` hosts; `k2` Sentinel `DnsEvents` non-PTR answer in ip6.arpa; `k3` Defender `EmailUrlInfo`+`UrlClickEvents` `.ip6.arpa` URLs.
- YARA (1 file, 2 rules): email/HTML carrying an ip6.arpa image link; known Campaign A/B zones and hosts.
- Suricata (1 file, 6 sids): DNS DGA-prefix on ip6.arpa, HTTP host + TLS SNI in reverse-DNS namespace, two known-zone lookups, and known phishing IPs (4100301-4100306).
- PEAK hunts (3): H1 A/AAAA answers in ip6.arpa; H2 staged Cloudflare-NS reverse zones; H3 image-only email links to reverse-DNS strings.
- `iocs.csv` (24 entries) — active + staged ip6.arpa zones, Cloudflare/IONOS IPs, IPv6 prefixes, `t-w.dev`, `hekeroyot[.]com`, detection regex and the RFC-violation note.
- `kill_chain.svg` — template A two-lane, canonical palette, two red anchors (wildcard A on ip6.arpa, image-only email link).

### Pedagogy
- Any `A`/`AAAA` answer from an `ip6.arpa` zone is an RFC violation with ~0% false positives — detect the answer type in the wrong namespace, not rotating hostnames.
- Wildcard + per-victim randomisation defeats blocklists by construction; the only scalable control is a namespace/answer-type rule (RPZ).
- CDN-NS delegation on a reverse zone is the pre-attack staging signal — hunting it pre-empts the campaign.
- Reputation laundering through trusted infra (`.arpa` has no WHOIS; Cloudflare lends trust) is the core evasion; never whitelist "infrastructure" namespaces at the gateway.

## 2026.06.02 — Day 36 — Aur0ra ransomware (no-rename in-place filecoder)

### Added
- `days/2026/06/2026-06-02_Aur0ra-NoRename-InPlace-Ransomware/` — CYFIRMA (2026-05-22) and pcrisk (VT-analysed) catalogued Aur0ra, an unattributed Windows x64 filecoder that encrypts files in place with no rename and no appended extension, deletes Volume Shadow Copies, and drops a single note `!!!README!!!DO_NOT_DELETE.txt` pointing to a Tor portal with a per-victim access key. Crime-economy slot #3; the design defeats extension-watch and canary-rename detection.
- Sigma (3): `01_aur0ra_inhibit_recovery_vss.yml` — VSS/wmic/wbadmin/bcdedit recovery destruction (T1490); `02_aur0ra_ransom_note_fileevent.yml` — ransom-note write (T1486); `03_aur0ra_removable_share_discovery.yml` — USB/share enumeration burst (T1120/T1135).
- KQL (4): `k1` recovery-destruction command lines; `k2` ransom-note fleet sweep; `k3` peripheral/share discovery; `k4` per-process mass file modification with no rename.
- YARA (1 file, 3 rules): Aur0ra ransom-note artifact, Aur0ra shadow-delete string heuristic, and the secondary Remus Stealer string rule (re-implemented from CYFIRMA).
- Suricata (1 file, 3 sids): secondary Remus Stealer C2 (`cheapoca.biz`) DNS + TLS-SNI, plus a low-priority direct-Tor-egress policy hint (Aur0ra negotiation is .onion-only).
- PEAK hunts (3): H1 recovery inhibition then encryption; H2 in-place no-rename modification burst (canary-aware); H3 removable-media + share recon.
- `iocs.csv` (19 entries) — Aur0ra note/strings/sample-hash/AV-labels (primary) and clearly-marked Remus Stealer rows (secondary).
- `kill_chain.svg` — template C single-lane, canonical palette, two critical-stage anchors (VSS deletion, in-place encryption).

### Pedagogy
- Extension-keyed and canary-rename ransomware detection is blind to no-rename in-place encryptors; detect by recovery inhibition and per-process modification rate.
- Shadow-copy deletion is the earliest, highest-fidelity, pre-encryption tell — page on it.
- During IR, scope by the note filename, not by a changed extension (there is none).
- One VT hash is brittle; behavioural rules survive the next repack.

## 2026.06.01 — Day 35 — GREYVIBE Russia-nexus AI-augmented espionage vs Ukraine

### Added
- `days/2026/06/2026-06-01_GREYVIBE-PhantomRelay-LegionRelay-Ukraine/` — WithSecure (2026-05-28) named GREYVIBE, a previously undocumented Russia-nexus cluster running Ukraine-focused intelligence collection since August 2025 via PhantomMail spear-phish, PhantomClick fake CAPTCHA and PrincessClub fake adult-club lures, dropping FallSpy (Android) and the PhantomRelay/LegionRelay PowerShell RATs. Distinctive for systematic GenAI tradecraft (ChatGPT/Gemini/Ideogram across lures, obfuscators, malware and post-compromise scripts).
- Sigma (3): `01_greyvibe_conhost_headless_powershell.yml` — conhost --headless launching a scripting host; `02_greyvibe_watchdog_schtask_3min.yml` — schtasks minute-cadence (/mo 1-3) PowerShell task; `03_greyvibe_onhost_artifacts_fileevent.yml` — PhantomRelay/LegionRelay artifact file names.
- KQL (4): `k1` conhost --headless; `k2` watchdog minute-cadence task; `k3` artifact filename sweep per host; `k4` C2/lure domain egress + hardcoded user-agents.
- YARA (1 file, 3 rules): PhantomRelay fingerprint, LegionRelay REST client, PhantomRelay watchdog.
- Suricata (1 file, 5 sids): RazerUpdater UA, anomalous Chrome/95 UA, PhantomRelayV1 /watchdog path, LegionRelay /api/register, DroneLink DNS.
- PEAK hunts (3): H1 conhost --headless LOLBIN; H2 minute-cadence watchdog task; H3 download cradle + Telegram dead-drop resolution.
- `iocs.csv` (28 entries) — lure/C2 domains, artifact paths, user-agents, REST endpoints, and infra/GenAI tradecraft notes; full hash/YARA set referenced at WithSecure GitHub.
- `kill_chain.svg` — template A, canonical palette, victim Windows chain vs GREYVIBE infrastructure lanes, IOC anchors.

### Pedagogy
- AI-built malware decays hashes/strings; hunt behaviour (conhost --headless, every-3-minute task, artifact names, hardcoded UAs).
- Self-healing persistence: the watchdog re-spawns the RAT every 3 minutes — exit criterion is absence of the task, not the process.
- Shared tooling (PhantomRelayLite across cybercrime clusters) is not shared identity; state attribution confidence per signal.
- PrincessClub grooming + FallSpy put the targeted person and their phone in scope, not only the endpoint.


## 2026.05.31 — Maintenance — Repo restructure: year/month sharding + auto-generated Pages gallery

### Changed
- `days/` sharded from flat `days/<slug>/` to `days/YYYY/MM/<slug>/` (34 cases migrated) so the tree stays browsable and the tooling stays fast as the journal grows. The layout is cosmetic — every link is computed from the file location and the chronology comes from each case's `date:` field, not its path.
- `tools/generate_index.py` — recursive `days/**` collection; `INDEX.md` rebuilt as a gallery (headline counters + recent thumbnail wall + collapsible by-month tables + facet links); now also patches an auto-generated gallery+counters block into `README.md` between `AUTOGEN:GALLERY` markers; the heavy inline 200+-row technique table was dropped in favour of `byTechnique/` links.
- `README.md` — added the live gallery block and updated the structure + naming-convention sections for the sharded layout.
- `tools/validate_all.py` and `tools/lint_all.sh` — unchanged; both already glob `days/**` recursively, so the deeper nesting is picked up automatically (verified).

### Added
- `tools/generate_site.py` + `docs/` — a self-contained, build-free GitHub Pages gallery (`index.html` + `data.json` + `thumbs/*.svg` + `.nojekyll`): filterable by actor/technique/platform/year, full-text search, headline counters, a kill-chain thumbnail per case, light/dark theming matched to the canonical SVG palette. Enable via Settings -> Pages -> branch `main`, folder `/docs`.

### Pedagogy
- Separate storage from presentation: shard the storage for scale, and put the "first-glance impact" into generated surfaces (gallery, counters, Pages) that aggregate across every shard so the viewer never feels the sharding.
- Keep one source of truth (the per-day frontmatter); generated indexes and the site are disposable and rebuilt on demand.


## 2026.05.31 — Day 34 — Black Shadow / Ababil of Minab — Iran-MOIS Recovery-Layer Destruction (vCenter VM Deletion, Veeam Backup Wipe, SSMS Database Drops)

### Added
- `days/2026/05/2026-05-31_BlackShadow-AbabilOfMinab-Recovery-Layer-Destruction/` — v9 weekend auto-rescue; first repo primary in slot #30 (backup/DR/hypervisor recovery-layer destruction). Gambit (2026-05-26) tied the pro-Iranian "Ababil of Minab" persona — which claimed the LA Metro/LACMTA breach confirmed 2026-04-02 — to Black Shadow (Iran MOIS, per INCD/ClearSky/Simon Kenin). The crew exfiltrated from US/Israel/Saudi/Turkey orgs and, at a subset, ran recovery-denial: authenticated vCenter VM Power Off + Delete from Disk, Disk Management volume deletion (relabeled "Minab"), SSMS Take Offline + DROP, Veeam "delete from disk" of the backup chain, and WipeFile erase of SQLBackup/web roots — scripted and hands-on-keyboard, with ChatGPT used to refine a Python script that dropped 58 SQL Server targets.
- Sigma (3): `01_blackshadow_wipefile_secure_delete.yml`; `02_blackshadow_veeam_backup_deletion.yml`; `03_blackshadow_proxychains_xfreerdp.yml`.
- KQL (4): vCenter Destroy_Task/PowerOffVM_Task burst; SQL SET OFFLINE/DROP DATABASE from non-DBA host; WipeFile + Veeam delete-from-disk; A.ExE tunneler C2 egress.
- YARA (1 file, 2 rules): customized Go tunneler "A.ExE" markers; persona/destruction-script markers.
- Suricata (1 file, 6 sids 7206001-7206006): DNS/TLS to nefeshhope.com; egress to tunneler/relay/staging IPs.
- PEAK hunts (3): cross-plane deletion burst; Veeam/WipeFile backup destruction; proxied RDP + tunneler.
- `iocs.csv` (15 entries) — C2 `members.nefeshhope[.]com`, IPs `46.30.190.173` / `45.150.108.61` / `91.193.19.198` / `31.172.87.20`, truncated hashes, tooling and TTP notes.
- `kill_chain.svg` — template A, viewBox 880x1280, canonical palette. Critical red nodes on VM Delete-from-Disk, SQL drop, and Veeam backup deletion. Verifier ran twice clean.

### Pedagogy
- Defend the recovery layer (backups, vCenter, Veeam) as a crown jewel — immutable, isolated, MFA-gated, recovery validated against an adversarial scenario.
- Detect on destructive verbs across the virtualization/DB/backup planes, not on malware — the chain is living-off-the-land.
- Multiple destructive techniques = a deliberate recovery-denial strategy; plan IR for parallel, compounding restoration.
- Hacktivist branding can be state cover; pivot on infrastructure/tooling overlap, not self-attribution.

## 2026.05.30 — Day 33 — AMOS / Atomic macOS Stealer — Malicious OpenClaw Skill SKILL.md Delivers a Multi-Key-XOR Universal Mach-O Wallet and Keychain Stealer

### Added
- `days/2026-05-30_AMOS-OpenClaw-Skill-macOS-Stealer/` — First repo primary in slot #14 (DFIR macOS), via the v9 weekend auto-rescue rule. AMOS (Atomic macOS Stealer), the dominant macOS infostealer-as-a-service, delivered through a malicious **OpenClaw skill `SKILL.md`** that social-engineers an AI coding agent — and through it the user — into installing a fake "prerequisite driver" from `openclawcli[.]vercel[.]app`, which pulls a universal Mach-O AMOS build from `91.92.242[.]30` via `curl | bash` and exfiltrates wallets and Keychains to `socifiapp[.]com/api/reports/upload` (Trend Micro, research 26/b). Triangulated with glueckkanja's RE of a previously undocumented AMOS variant (2026-04-10 — six obfuscation layers, multi-key length-tiered XOR, `cat login.keychain-db`, `ditto`/`curl` exfil of `/tmp/out.zip`, "Chip: Unknown" VM evasion) and Microsoft's ClickFix-macOS escalation (2026-05-06 — AMOS + MacSync + Shub via fake macOS-utility lures).
- Sigma (4): `01_amos_curl_pipe_shell_loader.yml` — Unix shell `-c` wrapping a `curl -fsSL` fetch; `02_amos_osascript_fake_password_dialog.yml` — `osascript display dialog` + `hidden answer` + password (GUI input capture); `03_amos_login_keychain_db_access.yml` — `cat`/`cp`/`ditto`/`zip` reading `Keychains/login.keychain-db`; `04_amos_curl_multipart_exfil.yml` — `curl` multipart upload of a `/tmp` zip or to `/api/reports/upload`.
- KQL (4): `k1_amos_curl_pipe_shell_loader.kql` — Defender XDR `DeviceProcessEvents` macOS loader sweep; `k2_amos_osascript_keychain_capture.kql` — osascript password dialog unioned with `login.keychain-db` access; `k3_amos_curl_multipart_exfil.kql` — multipart exfil sweep; `k4_amos_c2_network_egress.kql` — `DeviceNetworkEvents` egress to the OpenClaw/AMOS C2 set.
- YARA (1 file, 4 rules): `amos_macho_keychain_exfil_stealer` (universal/thin Mach-O + Keychain/exfil markers + `CCCrypt`/`SecKeychainFind`/`SecItemAdd`); `amos_openclaw_delivery_markers` (loader IP, vercel lure, report endpoint/fields); `amos_wallet_extension_targeting` (hardcoded MetaMask/Phantom/TronLink/Exodus/Coin98 extension IDs); `amos_macos_vm_evasion` ("Chip: Unknown" / "Intel Core 2" + stealer markers).
- Suricata (1 file, 6 sids 7203001-7203006): DNS for `openclawcli.vercel.app` and `socifiapp.com`; TLS SNI to `socifiapp.com`; HTTP GET loader pull from `91.92.242.30`; HTTP POST to `/api/reports/upload`; HTTP body match on the `report_file=` multipart field.
- PEAK hunts (3): `peak_h1_curl_pipe_shell_loader.md` — fleet hunt for `curl | bash` loaders outside a known-good install-domain allowlist; `peak_h2_osascript_keychain_cooccurrence.md` — osascript password dialog joined to `login.keychain-db` access within 30 min on the same host; `peak_h3_amos_c2_egress.md` — egress to the three campaign indicators.
- `iocs.csv` (~50 entries) — 18 SHA256 (16 Trend Micro OpenClaw builds incl. trojanized `ledger-wallet` + 2 glueckkanja RE hashes), loader host `91.92.242[.]30` + 10 loader paths, lure domain `openclawcli[.]vercel[.]app`, C2 `socifiapp[.]com` + `/api/reports/upload`, OpenClaw publisher accounts, 5 targeted wallet-extension IDs, exfil form fields, VM-evasion strings, and notes separating Trend Micro vs glueckkanja infrastructure plus the Microsoft ClickFix secondary.
- `kill_chain.svg` — template A, viewBox 880x1280, canonical palette. Left lane (victim Mac) holds seven stages with critical red badges on the osascript password capture, the curl loader, the Keychain/wallet theft, and the exfil POST. Right lane (AMOS MaaS + OpenClaw infrastructure) holds six ops boxes: the AMOS family, OpenClaw skill-marketplace abuse, the vercel fake-driver lure, the loader host, the C2 report endpoint (critical), and trojanized wallet replacement. Four cross-lane purple-dashed arrows; six vertical flow arrows; detection-anchors footer mapping every Sigma/KQL to its target. Verifier ran twice clean: viewBox 880x1280.

### Pedagogy
- macOS stealers ask for the password through a familiar `osascript display dialog` rather than breaking Gatekeeper — hunt the dialog (`hidden answer` under a non-Apple parent), not a signature bypass.
- `curl -fsSL <url> | bash` is the macOS LOLBAS-equivalent one-liner: cheap, high-fidelity, and present across AMOS, ClickFix, and cracked-app chains.
- Direct reads of `~/Library/Keychains/login.keychain-db` by anything other than `securityd` are near-zero-noise malicious — treat the path like LSASS handle access on Windows.
- AI-agent skills and project files (`SKILL.md`, `.cursorrules`, `CLAUDE.md`) are a delivery and persistence surface; ingestable agent instructions need package-dependency-grade supply-chain scrutiny.


## 2026.05.29 — Day 32 — MiniPlasma — CVE-2020-17103 Silent Regression Weaponized to SYSTEM on Fully Patched Windows 11

### Added
- `days/2026-05-29_MiniPlasma-CVE-2020-17103-Silent-Regression-NightmareEclipse/` — Chaotic Eclipse / Nightmare-Eclipse public PoC drop 2026-05-18 of MiniPlasma against CVE-2020-17103 in `cldflt.sys`; bug originally reported by Google Project Zero in Sep 2020 and supposedly patched Dec 2020 but ThreatLocker, Tharros Labs and BleepingComputer confirm exploitability on Windows 11 / Server 2022 / Server 2025 with May 2026 cumulative updates installed. Race in `HsmOsBlockPlaceholderAccess` driven by the undocumented `CfAbortHydration` IOCTL writes cross-boundary registry values, seeds the SYSTEM-default-profile `windir` env var at an attacker path containing a fake `System32\wermgr.exe`, and the next `\Microsoft\Windows\Windows Error Reporting\QueueReporting` tick launches the binary as `NT AUTHORITY\SYSTEM`. Huntress observed sibling tools BlueHammer / RedSun / UnDefend used in ITW intrusions against FortiGate SSL VPN-fronted environments since mid-April 2026; Microsoft patched RedSun + UnDefend out-of-band on 2026-05-21 (CISA KEV deadline 2026-06-03), MiniPlasma + YellowKey + GreenPlasma remain unpatched; actor threatened additional zero-day dump on 2026-07-14.
- Sigma (3): `01_miniplasma_volatile_environment_windir_write.yml` — `HKU\.DEFAULT\Volatile Environment\windir` value not under `C:\Windows` from non-session-0 baseline writer; `02_miniplasma_cloudfiles_blockedapps_write.yml` — `CloudFiles\BlockedApps` writes outside OneDrive client and gpsvc baseline; `03_miniplasma_wermgr_offpath_system_spawn.yml` — `wermgr.exe` with IL=System outside `System32` / `SysWOW64` or any shell child of `wermgr.exe` under SYSTEM.
- KQL (3): `k1_miniplasma_volatile_environment_windir.kql` — Defender XDR `DeviceRegistryEvents` 7-day sweep of windir writes outside `%SystemRoot%`; `k2_miniplasma_cloudfiles_blockedapps_writes.kql` — 7-day BlockedApps writes outside OneDrive / gpsvc baseline; `k3_miniplasma_wermgr_system_shell.kql` — unioned off-path-wermgr and shell-child-of-wermgr SYSTEM 7-day sweep.
- YARA (1 file, 3 rules): `miniplasma_pe_exploit_loader` (PE32+ MiniPlasma loader); `miniplasma_source_artifacts` (PoC source markers); `nightmare_eclipse_chain_marker` (shared persona / chain markers across MiniPlasma, YellowKey, GreenPlasma, BlueHammer, RedSun, UnDefend).
- Suricata (1 file, 4 sids 7202901-7202904): GitHub PoC repo path pull; PoC binary filename-pattern download; HTTP body content match on `HsmOsBlockPlaceholderAccess` + `Volatile Environment`; TLS SNI to operator personas.
- PEAK hunts (3): `peak_h1_windir_hijack_to_wermgr_chain.md` — windir write + off-path `wermgr.exe` co-occurrence within 24h; `peak_h2_cloudfiles_blockedapps_cross_boundary.md` — BlockedApps writes outside OneDrive / gpsvc baseline; `peak_h3_nightmare_eclipse_chain_cooccurrence.md` — at least two Nightmare-Eclipse anchors (MiniPlasma + RedSun/UnDefend + YellowKey) on the same host within 30 days.
- `iocs.csv` (~22 entries) — CVE-2020-17103 + CVE-2026-45585 (YellowKey) + CVE-2026-41091 (RedSun) + CVE-2026-45498 (UnDefend) + CVE-2026-33825 (BlueHammer); persona strings Chaotic Eclipse / Nightmare-Eclipse; exploit names MiniPlasma / YellowKey / GreenPlasma; routine `HsmOsBlockPlaceholderAccess`; primitive API `CfAbortHydration`; registry targets HKU `.DEFAULT\Volatile Environment\windir` and `Software\Policies\Microsoft\CloudFiles\BlockedApps`; scheduled-task path `\Microsoft\Windows\Windows Error Reporting\QueueReporting`; driver `cldflt.sys`; binary `wermgr.exe`; Defender safe baseline `4.18.26040.7`; FortiGate SSL VPN ITW vector; mitigation status; 2026-07-14 actor announcement.
- `kill_chain.svg` — template A, viewBox 880x1280, canonical palette. Left lane (victim host) holds seven numbered stages with critical red badges on the cldflt IOCTL race, the BlockedApps write, the windir hijack and the SYSTEM-shell finish. Right lane (operator + driver infrastructure) holds six ops boxes covering operator persona, vulnerable driver build, race window, CfAbortHydration primitive, WER scheduled task, and SYSTEM finish. Four cross-lane purple-dashed arrows; six vertical flow arrows; detection-anchors footer maps every Sigma rule to its target. Verifier ran twice clean: viewBox 880x1280.

### Pedagogy
- Silent regression is a real failure mode — a 2020 fix that worked in 2020 can stop working in 2026 without any visible vendor advisory; re-run historical PoCs against current builds on a quarterly cadence.
- Driver-side elevated-mode access checks (cldflt `CfAbortHydration` here) strip away the user-mode writer surface — key detections on the *target* of the registry write, never on the writer image.
- `HKU\.DEFAULT\Volatile Environment\windir` is a high-fidelity SIEM anchor at essentially zero noise cost — the same shape applies to `HKU\.DEFAULT\Environment\Path` and the HKLM session-manager environment.
- Treat the broader class "Microsoft-signed scheduled task that resolves `%windir%` then runs a Microsoft-signed binary under SYSTEM" (wermgr / dllhost / taskhostw / RuntimeBroker) as one detection family — MiniPlasma is one instance, not a one-off.


## 2026.05.28 — Day 31 — TrapDoor — Cross-Ecosystem Crypto and AI-Developer Stealer Across npm, PyPI and Crates.io

### Added
- `days/2026-05-28_TrapDoor-CrossEcosystem-Crypto-AI-Stealer/` — Socket Research Team blog 2026-05-24 on the cross-ecosystem supply-chain campaign Socket tracks as **TrapDoor**: 34 malicious packages and 384+ versions across npm (21), PyPI (7) and Crates.io (6), first observed on 2026-05-22 at 20:20:18 UTC with PyPI `eth-security-auditor@0.1.0`. Targets crypto, DeFi, Solana, Sui, Move and AI-tooling developers. Six-surface persistence (`.cursorrules`, `CLAUDE.md`, Git hooks, shell hooks, systemd, cron, SSH `authorized_keys`); npm shared payload `trap-core.js` (~48 485 bytes, 1149 LoC) with Fernet+ECDH crypto; Crates.io `build.rs` with hardcoded XOR key `cargo-build-helper-2026` exfiltrating Sui/Move keystores to GitHub Gists; PyPI auto-import that spawns `node -e` against attacker GitHub Pages host `ddjidd564.github[.]io`. Novel primitive: AI-coding-assistant prompt-injection via `.cursorrules` / `CLAUDE.md` with hidden instructions in zero-width Unicode (U+200B / U+200C / U+200D / U+FEFF). Operator persona `ddjidd564` also opened poisoned `.cursorrules` PRs against browser-use, langchain, langflow, llama_index, MetaGPT and OpenHands. Campaign marker `P-2024-001`. First repo case where AI-assistant project files are a first-class persistence vector.
- Sigma (3): `01_trapdoor_node_e_postinstall.yml` — `node -e` from python / npm / postinstall parent or with ddjidd564 substring; `02_trapdoor_ai_assistant_config_write.yml` — write of `.cursorrules` / `CLAUDE.md` / `AUDIT-MATRIX.md` / `BYPASS.md` / `PAYLOAD.md` / `SWARM.md` by `node` / `npm` / `python` / `cargo` / `bash` / `pwsh`; `03_trapdoor_ddjidd564_github_io_egress.yml` — outbound network connection to `ddjidd564.github.io` or command-line containing the campaign URL.
- KQL (3): `k1_trapdoor_node_e_pkgmgr_parent.kql` — Defender XDR `DeviceProcessEvents` 7-day fleet sweep of `node -e` from package-manager parents; `k2_trapdoor_ai_assistant_config_write.kql` — `DeviceFileEvents` 14-day AI-config writes by package-manager processes; `k3_trapdoor_ddjidd564_egress_correlation.kql` — `DeviceNetworkEvents` 14-day egress to `ddjidd564.github.io` correlated with package-manager initiator.
- YARA (1 file, 4 rules): `trapdoor_npm_trap_core_js` (heuristic shared payload anchor); `trapdoor_pypi_node_e_remote` (PyPI auto-import to attacker GitHub Pages); `trapdoor_crates_build_rs_xor` (Cargo build.rs XOR-and-Gist exfil); `trapdoor_ai_config_zwsp` (zero-width-Unicode-tagged AI-assistant config).
- Suricata (1 file, 6 sids 8260001-8260006): DNS query for `ddjidd564.github.io`; TLS SNI to the same; HTTP host header to the same; HTTP GET URI `/defi-security-best-practices/`; HTTP request from `reqwest` UA to `gist.githubusercontent.com`; HTTP request body carrying marker `P-2024-001`.
- PEAK hunts (3): `peak_h1_node_e_from_pkgmgr.md` — fleet hunt for `node -e` from a package-manager parent; `peak_h2_ai_assistant_config_zero_width.md` — fleet hunt for AI-config files carrying ≥2 distinct zero-width Unicode characters plus a campaign marker; `peak_h3_github_pages_payload_egress.md` — fleet hunt for 14-day egress to `ddjidd564.github.io` or `/defi-security-best-practices/*`.
- `iocs.csv` (~32 entries) — campaign payload host + URLs, GitHub operator persona, npm/PyPI publisher accounts, campaign marker, payload names, hardcoded XOR key, persistence file paths, attacker playbook documents, representative package names, plus contextual notes on persistence stack, cryptography, AI prompt-injection technique, exfil destinations, targeted credentials, detection-latency benchmark, PR-bombing targets, three secondaries (Laravel Lang, Gitea CVE-2026-27771, Checkmarx Jenkins TeamPCP), and the supply-chain genealogy.
- `kill_chain.svg` — viewBox 880x1280, two-lane vertical layout with adaptive light/dark palette. Left lane (victim developer workstation) holds seven numbered stages with three critical red badges (ecosystem trigger, AI-config plant, exfil). Right lane (TrapDoor operator infrastructure) holds six boxes covering operator persona, multi-registry waves, the shared `trap-core.js` payload (critical badge), the `ddjidd564.github.io` config + AUDIT-MATRIX playbook, the PR-bombing campaign against AI projects, and the exfil destinations + marker. Four cross-lane purple-dashed arrows for package ingress, payload pull, PR-injection direction (reverse), and exfil egress; vertical flow arrows between consecutive left-lane stages; detection-anchors footer mapping every Sigma, KQL, YARA, Suricata file and PEAK hunt to its anchor. SVG self-verifier ran twice clean: viewBox 880x1280, 18 rects.

### Pedagogy
- AI-coding-assistant project files (`.cursorrules`, `CLAUDE.md`) are now a first-class persistence surface — treat them with the same change-control discipline as `package.json`, `Dockerfile` and `.github/workflows/*.yml`.
- Zero-width Unicode (U+200B / U+200C / U+200D / U+FEFF) in any source-control-tracked text file is a red flag — add a CI lint that rejects PRs carrying these bytes outside a narrow allowlist.
- `build.rs`, `postinstall` and Python `__init__.py` are pre-runtime code paths — they execute before any EDR detection has steady-state context; detection must anchor on outbound behaviour (egress, persistence writes), not on the inbound package.
- Six persistence surfaces, not one — a TrapDoor sweep that only removes `.cursorrules` leaves Git hooks, shell hooks, systemd, cron and SSH `authorized_keys` intact; the IR runbook must enumerate all six.

---


## 2026.05.27 — Day 30 — BlackFile / UNC6671 / Cordial Spider — Vishing + AiTM SSO Compromise of Microsoft 365 and Okta with Programmatic SharePoint Exfiltration

### Added
- `days/2026-05-27_BlackFile-UNC6671-CordialSpider-SaaS-Extortion/` — Google Threat Intelligence Group (Larsen, McLellan, Stark, Ebreo) deep technical writeup 2026-05-15 of UNC6671, tracked in parallel by CrowdStrike Counter Adversary Operations as Cordial Spider (2026-05-01) and by Palo Alto Networks Unit 42 + RH-ISAC as CL-CRI-1116 (2026-05-19), of an English-speaking financially motivated extortion cluster operating under the BlackFile brand against Microsoft 365 and Okta tenants in North America, Australia and the United Kingdom. Workflow: vishing call to employee personal cell with IT-helpdesk passkey-or-MFA pretext → Tucows-registered SSO lookalike subdomain (per-victim `<org>.enrollms[.]com` / `passkeyms[.]com` / `setupsso[.]com`) → live AiTM credential and MFA capture → attacker-controlled MFA device enrollment and victim-device removal → inbox rules auto-delete `noreply@microsoft.com` and `no-reply@okta.com` notifications → internal directory scrape and SharePoint search for "confidential" / "SSN" / "MSA" / "merger" → programmatic SharePoint and OneDrive exfiltration via Microsoft Graph and SharePoint REST API using `python-requests/2.28.1` or `WindowsPowerShell/5.1` with spoofed `ClientAppId=d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office) → operator deliberately downshifts later intrusions to direct HTTP GET that emits `FileAccessed` rather than `FileDownloaded` to evade SOCs that demote that event class → extortion via Tox (early) then Session (Feb 2026+) → escalation via mass Gmail spam, hijacked internal mailbox spam, Teams hijack, executive voicemails and (rarely) swatting. Operator self-announced on the BlackFile DLS on 2026-05-11 that the brand is "shutting down... under this name" — case matters today because the IOC set has its highest diagnostic value over the 60-90 day mid-rebrand window.
- Sigma (3): `01_blackfile_aitm_lookalike_subdomain.yml` — network_connection from browser process to `.enrollms.com` / `.passkeyms.com` / `.setupsso.com` apex; `02_blackfile_browser_lookalike_url_argument.yml` — process_creation of msedge / chrome / firefox / brave / opera with lookalike domain in command-line URL; `03_blackfile_powershell_sharepoint_python_useragent.yml` — process_creation of PowerShell Invoke-WebRequest or Invoke-RestMethod against `.sharepoint.com` or `graph.microsoft.com` with `python-requests` / `WindowsPowerShell/5.1` / `Go-http-client` / `curl/` / `aiohttp/` User-Agent.
- KQL (3): `k1_m365uan_fileaccessed_python_useragent.kql` — OfficeActivity union of FileAccessed + FileDownloaded + FileSyncDownloadedFull + FilePreviewed with scripting-library UserAgent and spoofed-as-Microsoft-Office flag; `k2_m365uan_sharepoint_burst_unmanaged_device.kql` — high-volume SharePoint event burst (≥300 in 10 min) from IsManagedDevice=false with files-per-minute rate; `k3_entraid_mfa_register_after_failed_challenge.kql` — Entra ID SigninLogs MFA failure or abandoned challenge followed within 5 minutes by AuditLogs `User registered security info` / `Add registered security info`, with source-IP swap flag.
- YARA (1 file, 3 rules): `blackfile_phishing_kit_artifacts.yar` — apex-references rule (enrollms / passkeyms / setupsso + harvester boilerplate), exfil-script-boilerplate rule (Office ClientAppId spoof + scripting UA + FedAuth cookie + SharePoint REST or Graph endpoint), extortion-note-subject-template rule ("DATA BREACH 72 HOURS TO CONTACT US" + BlackFile / getsession.org / Tox); `filesize` bounded to keep performance reasonable.
- Suricata (1 file, 6 sids 9026001-9026006): TLS SNI to `.enrollms.com`, `.passkeyms.com`, `.setupsso.com`; IP rule to known UNC6671 exfil source IP `179.43.185.226` (commercial VPN); HTTP rule on `python-requests/2.28.1` UA to `.sharepoint.com`; HTTP rule on `WindowsPowerShell/5.1` UA to `.sharepoint.com`.
- PEAK hunts (3): `peak_h1_python_requests_sharepoint_fileaccessed.md` — scripting-library UA against SharePoint or OneDrive API with the FileAccessed-not-FileDownloaded discriminator; `peak_h2_mfa_device_register_after_failed_challenge.md` — Entra ID MFA registration within 5 minutes of MFA challenge failure with source-IP swap pivot; `peak_h3_lookalike_subdomain_tucows_recent.md` — DNS / proxy hunt for Tucows-registered apex domains less than 14 days old whose subdomain label literal-contains the organisation name.
- `iocs.csv` (~25 entries) — 3 lookalike apex domains, 1 anchor exfil IPv4, 7 attacker-fingerprint strings (Python UA, PowerShell UA, Microsoft Office ClientAppId GUID spoof, extortion-note subject template, Session messenger URL, Tox channel reference, FedAuth cookie reuse), 2 SharePoint search-query string anchors ("confidential", "SSN"), and 10+ contextual notes covering the DLS lifecycle, the brand-cooption with ShinyHunters, the Snarky Spider peer cluster, the workload list, and the cross-references to Day 23 (Storm-2949) and Day 27 (Operation Saffron).
- `kill_chain.svg` — viewBox 880x1280, two-lane vertical layout (victim M365 + Okta tenant on the left, BlackFile vishing + AiTM + DLS infrastructure on the right) with eight numbered victim stages including three critical red badges (AiTM credential and MFA capture, attacker MFA device enrollment, programmatic SaaS exfil), four right-lane operations boxes (vishing call center, Tucows lookalike apex domains, exfil destination with anchor IP and UA fingerprints, BlackFile DLS lifecycle plus mid-rebrand and comms), five cross-lane purple-dashed arrows from victim stages to operator-side boxes, vertical flow arrows between consecutive stages, and a detection-anchors footer mapping every Sigma, KQL, YARA, Suricata file and PEAK hunt to its purpose. SVG self-verifier ran twice: viewBox 880x1280, 16 rects, 3 top-level regions disjoint.

### Pedagogy
- The hardest-to-detect identity attack is the one with no malware on disk — UNC6671 / BlackFile compromises emit zero EDR-visible host indicators, and the whole detection burden falls on identity-provider and SaaS audit logs.
- `FileAccessed` is not benign when the User-Agent identifies a scripting library — UNC6671 deliberately switched to the request pattern that emits `FileAccessed` and most SOCs demote that event class to background noise; re-tier on UserAgent string, not Operation type.
- Phishing-resistant FIDO2 / passkey is the structural defense — push, SMS and TOTP MFA all fall to live AiTM; hardware-bound credentials cannot be replayed because the cryptographic challenge is tied to the device.
- Operator brand rebrand is a CTI signal not a closure — the BlackFile DLS announcement on 2026-05-11 says the cluster is in mid-rebrand; the IOC set is at its highest diagnostic value for the next 60-90 days; retro-hunt against 24 months of identity and SaaS telemetry before the rebrand resets the IOC clock.

---

## 2026.05.26 — Day 29 — VENOMOUS#HELPER / STAC6405 — Dual-RMM JWrapper-Packaged SimpleHelp + ScreenConnect IAB Operation

### Added
- `days/2026-05-26_VenomousHelper-STAC6405-Dual-RMM-IAB/` — Securonix Threat Research (Gaikwad, Sangwan, Beardslee) blog 2026-05-04, picked up by The Hacker News the same day and corroborated through Infosecurity Magazine, Dark Reading and TechNadu, on a 80+ org US-heavy phishing campaign codenamed VENOMOUS#HELPER (overlap with Sophos STAC6405 and prior Red Canary tracking) that runs an SSA-themed lure → compromised legitimate `.com.mx` hosts (`gruta.com.mx` harvester + `cubatiendaalimentos.com.mx` cPanel payload stage) → JWrapper-packaged SimpleHelp 5.0.1 installer signed by SimpleHelp Ltd / Thawte (cracked 2017 build, cert expired 2018) → `Remote Access Service` Windows service + `SafeBoot\Network` registry key + `sgalive` watchdog → renamed `wmic.exe.bak` SecurityCenter2 enumeration on a 67-second batch + `netsh wlan` 15 s + `elev_win.exe --mouselocation` 23 s (986 process-creation events/h with no operator) → ScreenConnect dropped silently via `msiexec /qn` from `Remote Access.exe` to a fallback relay `sslzeromail.run.place:8041 / 213.136.71.246` (IONOS DE AS8560). Case matters because it is the cleanest 2026 published example of dual-channel signed-RMM IAB tradecraft, the renamed-LOLBin (`wmic.exe.bak`) primitive, and the bi-directional use of SafeBoot persistence (Day 22 used it to disable EDR; today uses it to keep an RMM alive).
- Sigma (3): `01_wmic_rename_bak.yml` — process or file event for `wmic.exe.bak` under `System32\wbem\` (single highest-confidence host anchor per Securonix); `02_remote_access_safeboot_key.yml` — `SafeBoot\Network` subkey with RMM-themed service tokens (`Remote Access Service`, `JWrapper`, `SimpleHelp`, `ScreenConnect Client`); `03_jwrapper_simplehelp_installer.yml` — process creation under `C:\ProgramData\JWrapper-Remote Access\` for SimpleHelp/JWrapper binary names plus `elev_win --mouselocation` switch anchor.
- KQL (3): `01_defender_wmic_bak_masquerade.kql` — DeviceFileEvents + DeviceProcessEvents union anchor for `wmic.exe.bak`; `02_defender_simplehelp_udp_5555.kql` — DeviceNetworkEvents outbound UDP/5555 to 84.200.205.233 with parent-process pivot; `03_defender_screenconnect_msi_silent.kql` — `msiexec /i sc.msi /qn` parented by `Remote Access.exe` plus invariant install GUID `adbce2b92cb435b3` plus SfxCA rundll32 custom-action anchor.
- YARA (1 file, 1 rule): `venomous_helper.yar` — anchors on the campaign tenant `sh_app_profile=43794105…`, the ScreenConnect GUID `adbce2b92cb435b3`, the JWrapper tree (`JWrapper-Remote Access` + `JWAppsSharedConfig`), the SimpleHelp binary names (`SimpleGatewayService`, `SimpleService`, `session_win.exe`, `elev_win.exe`), the relay FQDN + port pair, and the firewall-exception naming convention `SHRemoteAccessService*`; filesize<200MB.
- Suricata (1 file, 4 sids 2026052601-2026052604): UDP/5555 to 84.200.205.233 (SimpleHelp primary); TCP/8041 to 213.136.71.246 (ScreenConnect relay); DNS query for `sslzeromail.run.place`; HTTP GET to compromised cPanel staging `~tiendazoycom/sns/` on `cubatiendaalimentos`.
- PEAK hunts (3): `peak_h1_wmic_bak_masquerade.md` — renamed-LOLBin fleet hunt with parent-chain pivot; `peak_h2_polling_cadence.md` — three deterministic cadences (15 s / 23 s / 67 s) from a single parent process tree; `peak_h3_safeboot_rmm_persistence.md` — SafeBoot\Network subkey RMM-token sweep with services + image-path follow-up.
- `iocs.csv` (~45 entries) — 2 IPs (SimpleHelp + ScreenConnect), 3 domains (gruta, cubatiendaalimentos, sslzeromail.run.place), 2 URLs (HTTP access + payload staging), 9 SHA256 hashes for the RAT components, 7 install-tree paths, 2 registry keys (Services + SafeBoot), 1 campaign tenant ID + 1 SimpleHelp package integrity token + 1 invariant ScreenConnect install GUID + 1 session GUID + 7 ScreenConnect RunRole GUIDs, plus the `sg_servers=` launch property and firewall exception naming convention, plus contextual notes on signer cert, JRE, and the three polling cadences.
- `kill_chain.svg` — viewBox 880x1280, two-lane vertical layout (victim Windows host on the left, attacker infrastructure on the right), six numbered victim stages with two critical red badges (service + SafeBoot persistence; operator-orientation burst stage extended), three numbered attacker-side stages with one critical red badge (ScreenConnect relay), three cross-lane arrows (compromised-host delivery, SimpleHelp UDP C2 paired with the persistence stage, ScreenConnect TCP relay paired with the MSI drop), detection-anchors footer mapping every Sigma, KQL, YARA, Suricata file and PEAK hunt to its purpose.

### Pedagogy
- Signed-software-as-LOLBin: a Thawte-issued certificate that expired in 2018 still triggers the blue "Verified publisher" UAC shield. Anchor detection on path + service name + behaviour, never on publisher reputation.
- Renamed LOLBin (`wmic.exe.bak`) is an extreme-confidence host IOC — generalize the hunt to `*.exe.bak`, `*.exe.copy`, `*.exe.old` under `System32\` and `System32\wbem\` to catch operator name rotation.
- Safe Mode persistence is bi-directional: Day 22 used it to keep an EDR-killer alive across Safe-Mode cleanup; today's RMM uses it the same way. Sweep all SafeBoot subkeys, not only security-tooling names.
- Cadence beats payload — a host emitting 986 process events/hour split exactly into 15 s / 23 s / 67 s timers, with no human at the keyboard, is always JWrapper-RMM automation under any inter-arrival anomaly model.

---

## 2026.05.25 — Day 28 — UAC-0057 / Ghostwriter — OYSTERFRESH JavaScript Loader and Registry-Persisted OYSTERBLUES Targeting Ukrainian Government via Prometheus Lures

### Added
- `days/2026-05-25_UAC0057-OYSTERFRESH-Prometheus-Ukraine/` — CERT-UA advisory #6315762 (22-May-2026) on a continuing Belarus-aligned UAC-0057 / Ghostwriter / UNC1151 spearphishing campaign against Ukrainian government organisations using Prometheus online-learning-platform lures. The chain runs from a compromised gov mailbox → PDF + link → ZIP → OYSTERFRESH JavaScript (wscript.exe) → stacked string-reversal + ROT13 + URL-decoding → OYSTERBLUES encrypted blob written into HKCU registry → OYSTERSHUCK in-memory decoder → Microsoft Edge Update masquerade persistence (Run key + scheduled task without genuine Core/UA suffix) → ~10-min HTTP POST host-profile heartbeat to Cloudflare-fronted .icu C2 → Cobalt Strike beacon delivered via eval() after operator triage. Case matters because it is the second UAC-0057 toolset disclosed in eight days alongside the ESET FrostyNeighbor PicassoLoader chain (14-May-2026) — the cluster runs parallel loader families for detection survivability against the same Ukrainian victim base.
- Sigma (3): `uac0057_wscript_js_from_archive.yml` — wscript.exe executing .js from user-writable archive paths (entry-point anchor); `uac0057_edge_update_masquerade_runkey.yml` — HKCU Run-key MicrosoftEdgeUpdate / EdgeApp value pointing outside the genuine Edge install path; `uac0057_scheduled_task_edge_update_masquerade.yml` — scheduled task MicrosoftEdgeUpdateTaskMachine without Core/UA suffix whose action launches wscript.exe.
- KQL (3): `uac0057_wscript_js_from_archive_post_to_icu.kql` — Defender XDR wscript.exe + .js execution followed by HTTP POST to *.icu within 5 minutes; `uac0057_run_key_edge_masquerade.kql` — DeviceRegistryEvents Run-key Edge masquerade hunt with genuine-path filter; `uac0057_icu_dns_post_correlation.kql` — DNS query to *.icu correlated with HTTP POST egress within 60 seconds.
- YARA (1 file, 1 rule): `uac0057_oysterfresh_js_loader_2026` — OYSTERFRESH JS anchored on the stacked decode chain (string reverse + ROT13 lookup + decodeURIComponent), persistence anchors (Run key + scheduled task masquerade), COM-object execution primitives (WScript.Shell, ActiveXObject, RegWrite), .icu C2 strings and HTTP POST + XMLHTTP/fetch primitives, with required-set logic plus a discovery anchor to bound false positives; filesize < 2MB.
- Suricata (1 file, 5 sids 8240001-8240005): DNS query for .icu TLD; TLS SNI to .icu host; HTTP host header for .icu host; HTTP POST to .icu host (high-confidence OYSTERBLUES exfil anchor); HTTP request with WinHttp / wscript / XMLHTTP user-agent to .icu host.
- PEAK hunts (3): `peak_h1_wscript_js_from_archive.md` — 90-day retro on wscript.exe + .js from archive-extraction paths; `peak_h2_edge_update_masquerade_runkey.md` — HKCU Run-key Edge-update masquerade sweep across the estate; `peak_h3_icu_post_cadence.md` — sustained ~10-minute HTTP POST cadence to a .icu FQDN as the OYSTERBLUES beacon signature.
- `iocs.csv` (~30 entries) — family-name strings (OYSTERFRESH / OYSTERBLUES / OYSTERSHUCK / CSBEACON / PicassoLoader), lure brand strings (prometheus, Ukrtelecom), persistence regkeys (HKCU Run\MicrosoftEdgeUpdate, EdgeApp, MicrosoftEdge), persistence paths (MicrosoftEdgeUpdate.exe, EdgeApp.exe, scheduled-task path, drop locations), execution primitives (wscript.exe, WScript.Shell, WScript.Network, eval(, decode-chain primitives), .icu TLD + Cloudflare fronting infra-pattern note, CVE-2024-42009 Roundcube feeder reference, and cluster-alias / Belarus-attribution provenance notes.
- `kill_chain.svg` — viewBox 880x1200, two-lane vertical layout (victim Windows endpoint left, attacker infrastructure right), six numbered victim stages with critical red badges on the registry-persistence and Cobalt Strike stages, four numbered attacker stages covering the compromised gov mailbox sender pivot, the Cloudflare-fronted .icu delivery + C2 cluster, operator triage tier, and Cobalt Strike team server; cross-lane arrows for delivery + C2 + Cobalt Strike beacon traffic; footer band mapping every Sigma, KQL, YARA, Suricata file and PEAK hunt to the stage it instruments.

### Pedagogy
- Registry-resident encrypted payloads (T1027.013 + T1112) defeat disk-based detection — hunt on abnormally large `HKCU\Software\*` registry value sizes, not on filesystem hashes that the operator rotates faster than your YARA cycle.
- Microsoft Edge Update masquerade is now a cross-cluster persistence pattern in 2026 — the discriminator is the install path (genuine Edge under Program Files) and the task name suffix (genuine tasks end in `Core` / `UA`); attacker variants omit both.
- Ukraine-only geofencing on the delivery server means EU/US sandbox detonation will report false-negative — route the sample to a Ukrainian-IP sandbox or detonate offline before declaring an attachment benign.
- Compromised gov mailboxes break SPF/DKIM/DMARC reputation defences — anchor on the link + attachment semantic, not on sender domain reputation.

---

## 2026.05.24 — Day 27 — Operation Saffron — First VPN Anonymization-as-a-Service Takedown by Europol, France, Netherlands and FBI

### Added
- `days/2026-05-24_OperationSaffron-FirstVPN-Takedown/` — Europol + Eurojust JIT (France BL2C + Netherlands NHTC) + FBI dismantle First VPN Service on 19-20 May 2026 with simultaneous FBI FLASH-20260521-001 release; 33 servers seized across 27 countries, four customer-facing domains (1vpns.com/.net/.org + 1jabber.com) plus onion mirrors taken offline, Ukrainian administrator interviewed in-country, user database extracted and partitioned across 83 intelligence packages naming 506 users; service active since 2014 and used by 25+ ransomware groups (Avaddon, Phobos) according to the FBI flash. Case matters because the flash releases a 98-IP exit-node list that defenders can drop into a watchlist for 24-month retro hunts.
- Sigma (3): `firstvpn_corp_vpn_auth_from_known_node.yml` — successful corporate VPN auth where source IP is in the FBI current-IP list; `firstvpn_outbound_dns_corp_endpoint.yml` — DNS query from corp endpoint to 1vpns.* or 1jabber.com (insider-risk anchor); `firstvpn_brute_force_burst_known_node.yml` — failed auth from First VPN IP (apply >=20-in-60-min count at SIEM aggregation layer).
- KQL (3): `firstvpn_signin_from_known_node.kql` — Entra ID successful sign-in from FBI IP list with 730-day lookback; `firstvpn_failed_then_success_burst.kql` — same UPN with >=5 failures then a success from a First VPN IP inside 24h; `firstvpn_corp_endpoint_outbound.kql` — DeviceNetworkEvents outbound from managed endpoint to First VPN IP (insider exfil anchor).
- YARA (1 file, 1 rule): `first_vpn_service_client_config_2026` — on-disk First VPN client configuration artifacts (OpenVPN profile, WireGuard config, VLess+Reality XTLS JSON, Outline SIP002) anchored on seized domains and customer-support communication accounts; filesize<256KB; forensic artifact-discovery rule.
- Suricata (1 file, 8 sids 8230001-8230008): DNS queries to four seized domains; TLS SNI to 1vpns.*; HTTP host to 1vpns.* / 1jabber.com; outbound IP egress to current 33-IP list; inbound from current IP list to perimeter auth services (SSH/HTTPS/RDP/8443).
- PEAK hunts (3): `peak_h1_corp_auth_from_firstvpn.md` — 24-month retro on corporate auth from First VPN exit IP; `peak_h2_insider_outbound_to_firstvpn.md` — insider/contractor reaching First VPN from inside corp; `peak_h3_bruteforce_burst_then_success.md` — failed-then-success burst as affiliate dwell-time anchor.
- `iocs.csv` (~125 entries) — full FBI FLASH IOC set: 33 current exit-node IPs, 65 historical exit-node IPs (May 2026 cutoff), four seized domains, ten communication-channel anchors (Jabber, Telegram, ICQ, email, URL), two forum-marketing anchors (Exploit.in, XSS.is), explanatory notes on pricing tiers and payment rails.
- `kill_chain.svg` — viewBox 880x1180, three-lane GitHub-friendly adaptive light/dark palette, ransomware-affiliate lane left with seven numbered stages including critical stage badges for brute force / auth / pivot, First VPN infrastructure lane center (web, admin, support, exit-node cluster, protocol catalogue), victim corp network lane right with six stages including critical badges for tier-0 / pre-encryption / encryption, dedicated law-enforcement-takedown panel at the bottom with three stages (seizure, admin interview, customer notification), bidirectional orange arrow on ransom-negotiation traffic, detection-anchors footer mapping all rules and hunts to IOC anchors.

### Pedagogy
- An IOC dump from a multi-year LE operation is the highest-value single CTI input you will receive this quarter — re-run the FBI IP list against 24 months of identity, perimeter, and EDR telemetry, not the default 90-day window.
- Identity-provider geolocation is not a detection signal when the adversary uses anonymization-as-a-service — the exit-node country is the wrong anchor; the IP set is the right one.
- VLess+Reality is the operationally important obfuscation pattern of 2026: the proxy presents the real ServerHello of a high-reputation site, so SNI-only proxies cannot identify it; defense moves to JA4 fingerprint plus destination IP plus behavioral anomaly.
- Bulletproof anonymization services are the connective tissue of the ransomware economy — when one falls, every affiliate using it loses operational cover at the same time and the 30-90 day post-takedown window is the widest defender opportunity of the year.

---

## 2026.05.23 — Day 26 — SonicWall Gen6 SSL-VPN MFA Bypass (CVE-2024-12802) First In-the-Wild Exploitation by Akira-Aligned Affiliate

### Added
- `days/2026-05-23_SonicWall-Gen6-MFA-Bypass-CVE-2024-12802/` — ReliaQuest Threat Research write-up (Capraro and Luikey, 2026-05-19) of the first publicly documented in-the-wild exploitation of CVE-2024-12802, an authentication bypass in SonicWall SSL-VPN appliances where MFA is enforced per AD login format (UPN vs SAM) rather than per identity. The Gen6 firmware patch alone does not remediate the vulnerability — six manual LDAP reconfiguration steps are required and no standard patch-management workflow verifies them, leaving "patched" devices fully exploitable. TTPs consistent with Akira / Storm-1567 affiliate ecosystem; one escalation case reached a domain-joined file server via RDP using a reused local-administrator password within 30 minutes of initial VPN authentication, and EDR blocked subsequent Cobalt Strike beacon plus BYOVD chain.
- Sigma (3): `sonicwall_sslvpn_cli_session_brute_force.yml` — `sess="CLI"` scripted-authentication burst anchor; `sonicwall_sslvpn_upn_login_no_otp.yml` — successful UPN login without correlated OTP entry as the MFA-bypass discriminator; `post_vpn_rdp_with_local_admin_to_file_server.yml` — RDP from VPN-assigned IP using local-admin account into server tier.
- KQL (3): `sonicwall_cli_session_burst_brute_force.kql` — Sentinel CLI-session brute force by source IP within 10 minutes; `sonicwall_mfa_bypass_upn_no_otp.kql` — UPN login leftanti-joined to OTP entry within ±60s; `vpn_to_internal_rdp_pivot_30min.kql` — Defender XDR VPN-to-server-tier RDP within 30 minutes.
- YARA (1 file, 2 rules): `SonicWall_EDR_Killer_Hash_Anchors_2026` — exact SHA256 anchors for the two ReliaQuest-published payloads; `Akira_Ecosystem_BYOVD_EDR_Killer_Heuristic_2026` — heuristic guardrail keyed to BYOVD driver names from the Day 16/19/22 catalogue.
- Suricata (1 file, 4 sids 8230001-8230004): source-IP IOC rules for both ReliaQuest-published IPs plus Cobalt Strike default-URI and Akira-ecosystem TLS-SNI heuristics.
- PEAK hunts (3): `peak_h1_cli_session_brute_force.md` — every observed compromise leaves the `sess="CLI"` anchor before first success; `peak_h2_mfa_bypass_silent_login.md` — UPN-login-without-OTP as the high-confidence CVE-2024-12802 fingerprint; `peak_h3_vpn_to_rdp_30min_pivot.md` — VPN-to-internal-RDP pivot inside the 30-minute breakout window.
- `iocs.csv` (14 entries) — full IOC set covering the CVE, the two source IPs, both payload SHA256 anchors, the SonicWall log strings and Event IDs, plus contextual notes on Akira-affiliate TTP overlap and the Akira-ecosystem BYOVD catalogue.
- `kill_chain.svg` — adaptive light/dark palette, two lanes (victim host left, attacker C2 right), 9 numbered stages with EDR-blocked stages 6 and 7 highlighted in red, attacker hub box plus 6-step remediation reference box, and a footer detection-anchors panel mapping directly to the sigma/kql/yara/suricata files in the folder.

### Pedagogy
- A passed firmware version is not remediation when the vendor advisory requires post-patch configuration changes; audit every edge-device advisory for the phrase "additional manual steps" before closing as done.
- MFA enforced per login format rather than per identity is a model bug — same exposure shape may exist on any appliance that supports multiple AD login formats.
- `sess="CLI"` in SonicWall authentication logs is the highest-confidence early-stage anchor for this class of attack and most organizations do not monitor the session-type field today.
- Single reused local-administrator password collapses VPN access into lateral movement in under 30 minutes; LAPS or equivalent is the structural remediation.
- End-of-life edge hardware (Gen6 EoL 2026-04-16) is a perpetual exposure especially in M&A-inherited environments; plan replacement as a hard deadline.

---

## 2026.05.22 — Day 25 — Red Lamassu / Calypso APT — JFMBackdoor (Windows side-load) and Showboat (Linux kworker masquerade) targeting Asian telecoms

### Added
- `days/2026-05-22_RedLamassu-JFMBackdoor-Showboat-Telecom/` — PwC Threat Intelligence and Lumen Black Lotus Labs published tandem analyses on 2026-05-21 of Red Lamassu (Calypso APT), a PRC-aligned (Sichuan/Chengdu) cluster active since at least mid-2022 against telecommunications and government in Kazakhstan, Afghanistan, India, Azerbaijan and the Middle East. Toolkit: JFMBackdoor (Windows) delivered via fltMC.exe side-load of attacker FLTLIB.dll with XOR key `Zs0@31=KDw.*7ev` and CppServer TCPSession/WSSession/WSSSession transports; Showboat / kworker (Linux) ELF post-exploitation framework with XOR key `look me, AV!`, SOCKS5+portmap pivots, and Pastebin dead-drop via the hide command.
- Sigma (3): `jfmbackdoor_fltmc_sideload_fltlib_dll.yml` — fltMC.exe executing from a non-System32 user-writable path; `jfmbackdoor_artifact_drop_temp_chain.yml` — hidden PowerShell + Invoke-WebRequest fetching the four staging artefacts (FLTLIB.dll, flt.bin, scr.mui, fltMC.exe); `showboat_kworker_pastebin_deaddrop.yml` — user-space process named kworker calling curl/wget against Pastebin or similar dead-drop sites.
- KQL (3): `jfmbackdoor_fltmc_sideload_chain.kql` — DeviceFileEvents %TEMP% staging of 3+ side-load artefacts joined to DeviceProcessEvents fltMC.exe outside System32 within 1 h; `red_lamassu_c2_egress_telecom_themed_domains.kql` — DeviceNetworkEvents egress to the eight Red Lamassu C2 domains and the 12 IP anchors; `showboat_kworker_anomalous_egress.kql` — user-space kworker process joined with outbound HTTPS/SOCKS5 in 5-minute windows on Linux MDE.
- YARA (1 file, 3 rules): `RedLamassu_JFMBackdoor_PE_Heuristic_2026` (PE + XOR key + CppServer class names + side-load artefact strings), `RedLamassu_Showboat_ELF_Heuristic_2026` (ELF + `look me, AV!` + kworker + SKS/MAP + sleep-config fields), `RedLamassu_OpenDirectory_KnownHashes_2026` (11 SHA256 anchors for the open-directory artefacts).
- Suricata (1 file, 10 sids 8220001-8220010): DNS for the eight Red Lamassu C2 FQDNs; TLS SNI match; plain-HTTP GET against 23.27.201.160:8000 for `flt.bin`/`FLTLIB.dll`/`scr.mui`/`fltMC.exe`; outbound IP anchors for the three primary Showboat origins; X.509 fingerprint anchor for `27df475626aafce2…`.
- PEAK hunts (3): `peak_h1_jfmbackdoor_fltmc_sideload.md` — side-load chain inside 1 h with memory-first action; `peak_h2_showboat_kworker_masquerade.md` — kworker user-space anchor with outbound egress, treating Outlook/mail/edge devices as pivot points; `peak_h3_red_lamassu_cert_pivot.md` — X.509 fingerprint pivot across 20+ historic C2 nodes.
- `iocs.csv` (52 entries) — 11 SHA256s (incl. JFMBackdoor PE 176aec5d…), eight C2 domains, 17 IPv4 anchors covering 2023-2026, four string anchors (XOR keys + `C:\Users\public\jfm`), four registry/path anchors, four X.509 fingerprint/serial anchors.
- `kill_chain.svg` — viewBox 880x1180, GitHub-friendly adaptive light/dark palette, nine numbered stages on the victim-host lane (open-directory staging through Showboat lateral and collection), C2 lane on the right with three panels (JFMBackdoor C2, Showboat C2, open-directory + Pastebin dead-drop), bidirectional yellow arrows on JFMBackdoor C2 and Showboat SOCKS5 channels, footer detection-anchors box mapping Sigma + KQL + YARA + Suricata + the three PEAK hunts and the certificate-fingerprint pivot rule.

### Pedagogy
- DLL side-loading is the dominant Windows-implant evasion of 2026 — anchor on the legitimate-binary path anomaly (fltMC.exe outside System32), not on the malicious DLL hash, which rotates faster than detection content.
- Real Linux `kworker` threads are kernel-space only — any user-space process whose `comm` is kworker is the highest-confidence masquerade anchor; hook `execve` so the actual `exe` path is captured.
- X.509 certificate fingerprints outlast IP rotation — Red Lamassu shared one self-signed `My Organization` SHA256 across 20+ C2 nodes for three years; hunt by certificate, by serial number for fronted services, not by hostname.
- A single open-directory IP cascaded into a complete two-platform toolkit story — exhaust X.509 pivots before the binaries when you find an exposed staging host.

---

## 2026.05.21 — Day 24 — TeamPCP 48-Hour Mega-Campaign — actions-cool Tag Poisoning, durabletask PyPI Worm, Nx Console VS Code Extension and the GitHub Internal Repo Breach

### Added
- `days/2026-05-21_TeamPCP-48h-Multi-Vector-SupplyChain/` — TeamPCP / UNC6780 (Google Threat Intelligence Group) ran four overlapping supply-chain intrusions between 18-May 12:36 UTC and 20-May 2026, all converging on shared C2 spine `check.git-service.com`, `t.m-kosche.com` and the Day-18 legacy C2 IP `83.142.209.194`. Vendor postmortems: StepSecurity (18-May, actions-cool tag poisoning with 68 imposter commits and bun-plus-`/proc/<Runner.Worker PID>/mem` secret scrape), Wiz (19-May, `durabletask` v1.4.1-v1.4.3 PyPI worm with AWS SSM and Kubernetes lateral propagation), Aikido Security (20-May, `nrwl.angular-console v18.95.0` Marketplace candidate for the GitHub internal-repo breach), GitHub corporate statement (20-May, ~3,800 internal repos exfiltrated).
- Sigma (3): `actions_cool_bun_runner_secret_dump.yml` — python3 reading `/proc/<other PID>/mem` from a Runner.Worker context anchor; `teampcp_rope_pyz_python_pyz_exec.yml` — python3 executing `/tmp/managed.pyz` or `/tmp/rope-*.pyz`; `teampcp_infection_marker_dotcache_sys_update.yml` — file_event creation of `~/.cache/.sys-update-check` and `~/.cache/.sys-update-check-k8s`.
- KQL (3): `teampcp_t_m_kosche_egress_join_developer_endpoint.kql` — Defender XDR egress to the three IoC anchors joined with developer endpoint process context within 30 min; `teampcp_vscode_extension_anomalous_egress_after_install.kql` — extension folder write followed by Code.exe-node-child egress to a FQDN not on the tenant `<add_known_vscode_telemetry>` allowlist within 30 min; `teampcp_durabletask_install_burst_then_pyz_drop.kql` — `pip install durabletask` or wheel-SHA match followed within 60 min by `/tmp/*.pyz` drop and python3 exec.
- YARA (1 file, 2 rules): `TeamPCP_rope_pyz_Heuristic_2026` (zipapp PK plus `__main__.py` plus 2+ C2 anchors plus 1+ runtime artefact plus 2+ credential-path anchors plus filesize cap) and `TeamPCP_rope_pyz_Known_Hashes_2026` (rope.pyz plus the three durabletask wheel SHA256 anchors).
- Suricata (1 file, 6 sids 8210001-8210006): DNS for the two TeamPCP FQDNs, TLS SNI match, legacy C2 IP, HTTP POST `/api/public/version` exfil, HTTP `/audio.mp3` destructive trigger and `/v1/models` killswitch endpoints.
- PEAK hunts (3): `peak_h1_imposter_commit_runner_memory_read.md` — actions-cool workflow run plus bun install plus python3 `/proc/<PID>/mem` read; `peak_h2_rope_pyz_worm_dev_endpoints.md` — durabletask install plus `/tmp/*.pyz` drop plus infection marker plus cred-path reads with isolation-before-revocation rule; `peak_h3_vscode_marketplace_anomalous_egress.md` — extension write plus anomalous Code.exe-node-child egress within 30 min.
- `iocs.csv` (97 entries) — three C2 anchors, six payload SHA256s, six runtime paths, the Nx Console v18.95.0 string anchor, all 53 actions-cool/issues-helper imposter commits and all 15 actions-cool/maintain-one-comment imposter commits with their tag-to-SHA mapping, plus operational notes on the repo-pinning remediation.
- `kill_chain.svg` — viewBox 880x1280 GitHub-friendly adaptive light or dark palette, three parallel victim lanes (Marketplace extension, tag poisoning, PyPI worm) numbered 1-12 with one impact box for the GitHub corporate breach, shared C2 spine on the right with domains plus URL paths plus payload artefacts plus imposter-commit anchors plus operator monetisation, bidirectional yellow C2 arrows on the bun-stage and rope.pyz-stage, footer detection-anchors box mapping Sigma plus KQL plus YARA plus Suricata plus the three PEAK hunts and the isolation-before-revocation IR rule.

### Pedagogy
- Tag mutability is the structural weakness — pinning by tag is trust-on-first-use; only a verified full commit SHA is a stable pin, and SLSA provenance does not catch a maintainer-credentialled tag rewrite.
- `/proc/<PID>/mem` is the GitHub Actions secret jar — once arbitrary code runs in the runner with bun or python3, every decrypted secret in Runner.Worker memory is reachable.
- VS Code Marketplace extensions execute pre-auth on the developer endpoint with full file-system and network access — eleven-minute Marketplace detection windows are exposure windows, not safety margins.
- Shared exfil infrastructure across npm, PyPI and Marketplace in 48 hours confirms a single operator — treat any egress to `t.m-kosche.com` or `check.git-service.com` as TeamPCP across vector lines.

---

## 2026.05.20 — Day 23 — Storm-2949 — From SSPR-Abused Identity to Cloud-Wide Breach across Microsoft 365 and Azure

### Added
- `days/2026-05-20_Storm-2949-Cloud-Identity-SSPR/` — Microsoft Threat Intelligence and Microsoft Defender Security Research disclosure (18-May-2026) of Storm-2949, a financially motivated cluster that chained vishing plus Self-Service Password Reset (SSPR) abuse, MFA method strip and Microsoft Authenticator rebind, Microsoft Graph enumeration, OneDrive plus SharePoint bulk exfiltration, App Service `publishxml`, Key Vault secret burst, SQL plus Storage exfiltration, VMAccess plus Run Command plus IMDS token theft, and ScreenConnect endpoint persistence. The case is the canonical 2026 zero-CVE identity-as-perimeter intrusion and complements Day 9 (CodeOfConduct AiTM) as the SSPR-based counterpart to proxy-based AiTM.
- Sigma (3): `storm2949_run_command_imds_token_request.yml` — PowerShell child of `WindowsAzureGuestAgent.exe` hitting `169.254.169.254/metadata/identity` (high); `storm2949_authenticator_rebind_after_mfa_strip.yml` — Entra AuditLogs `Register Microsoft Authenticator app` event with service-account exclusion (high); `storm2949_defender_av_tamper_via_run_command.yml` — `Set-MpPreference -DisableRealtimeMonitoring` invoked from a Run Command shell (critical).
- KQL (3): `storm2949_arm_publishxml_keyvault_storage_chain.kql` — ARM control-plane burst (publishxml plus KV plus listkeys plus SQL firewall) within 30 min on `CloudAuditEvents`; `storm2949_sspr_mfa_strip_rebind_chain.kql` — SSPR plus MFA-method strip plus Authenticator rebind within 5 min on the same user; `storm2949_onedrive_bulk_download_then_arm_pivot.kql` — OneDrive or SharePoint bulk download followed by ARM pivot within 60 min by the same identity.
- YARA (1 file, 2 rules): `Storm2949_ScreenConnect_Masquerade_Heuristic_2026` (PE plus ConnectWise vendor anchors plus Windows-component masquerade strings plus Defender-tamper command anchors) and `Storm2949_OperatorInfra_IP_Anchor_2026` (operator IPs `185.241.208.243`, `176.123.4.44`, `91.208.197.87` plus IMDS endpoint anchor).
- Suricata (1 file, 4 sids 8230001-8230004): egress IP anchors for the three operator IPs and an HTTP IMDS token request anchor visible in east-west cloud mirroring.
- PEAK hunts (3): `peak_h1_sspr_mfa_strip_rebind.md` — SSPR plus MFA strip plus Authenticator rebind chain; `peak_h2_arm_credential_burst.md` — ARM control-plane credential burst; `peak_h3_vmaccess_runcommand_imds.md` — VMAccess local admin plus Run Command IMDS token request.
- `iocs.csv` (31 entries) — three operator IPs, eight canonical ARM operation anchors, IMDS endpoint and header strings, Defender-tamper command anchors, event-log-clearing anchors, ScreenConnect installation paths, behavioural and IR-operational notes.
- `kill_chain.svg` — viewBox 880x1280 GitHub-friendly adaptive light or dark palette, eleven numbered stages on the victim identity and cloud lane (vishing through long-tail exfil), operator panels on the right (egress IPs, ARM operations weaponised, endpoint capability with ScreenConnect, long-tail exfil with IMDS anchor), bidirectional yellow C2 arrows on every operator-touching stage, and a footer detection-anchors box mapping identity, ARM control plane, VM bridge anchors and the dual-key Storage rotation rule.

### Pedagogy
- Identity is the new perimeter — the entire cloud-plane attack chain uses zero CVEs; every primitive is a documented Azure feature used with valid privileged credentials, so detection has to live in `CloudAuditEvents`, `AzureActivity` and Key Vault diagnostic logs, not in EDR.
- The MFA method strip plus Authenticator rebind within five minutes on a single principal is the highest-confidence SSPR-takeover anchor and applies far beyond Storm-2949.
- PowerShell parented by `WindowsAzureGuestAgent.exe` requesting an IMDS managed-identity token is a one-line hunt for cloud-to-host pivot.
- Rotate both Storage account keys after `listkeys` abuse — rotating one leaves SAS tokens signed with the other still valid; extend Key Vault diagnostic retention to one year before an incident, not after.

---

## 2026.05.19 — Day 22 — Embargo Ransomware Rust MDeployer + MS4Killer with Safe Mode Boot BYOVD (ESET + TRM Labs)

### Added
- `days/2026-05-19_Embargo-Rust-SafeMode-BYOVD/` — Rust RaaS Embargo (ESET WeLiveSecurity 23-Oct-2024, Holman and Zvara) closes the four-driver BYOVD catalogue of the diary (Akira/DragonForce truesight.sys, Warlock nseckrnl.sys, Qilin rwdrv+hlpdrv from Day 16, now Embargo probmon.sys) and introduces the first repo entry pairing `T1562.009 Safe Mode Boot` with BYOVD. TRM Labs (8-Aug-2025) assesses Embargo as a likely BlackCat/ALPHV rebrand via Rust + leak-site + on-chain wallet overlap, with USD 34.2 M cumulative incoming volume. US healthcare victims include Memorial Hospital and Manor (Bainbridge GA, 1.15 TB, 120085 individuals).
- Sigma (3): `embargo_safemode_boot_persistence.yml` — bcdedit safeboot Minimal / sc create irnagentd / reg \Safeboot\Network\irnagentd / reg delete WinDefend (critical); `embargo_mdeployer_debug_drops.yml` — file creation of canonical MDeployer filenames in `C:\Windows\Debug\` (high); `byovd_probmon_driver_load.yml` — kernel driver load of Sysprox.sys / Sysmon64.sys / Proxmon.sys from non-canonical path or matching probmon.sys v3.0.0.4 hash or ITM System signer (critical).
- KQL (3): `embargo_safemode_chain_defender_xdr.kql` — bcdedit + sc + reg Safeboot + shutdown chain join within 10 min; `embargo_debug_dir_drops_join_scheduled_task.kql` — `C:\Windows\Debug\` drops joined with `schtasks Perf_sys` creation; `byovd_probmon_driver_load_defender_xdr.kql` — non-canonical kernel driver load + AV process termination join within 15 min.
- YARA (1 file, 2 rules): `Embargo_MDeployer_MS4Killer_Heuristic_2026` (MDeployer + MS4Killer RC4 keys + XOR string anchors + mutex lyric anchors + minifilter API imports + service-name rotation + filesize cap) and `Embargo_MDeployer_MS4Killer_Known_Hashes_2026` (SHA1/SHA256 anchors for ESET-published samples and probmon.sys).
- Suricata (1 file, 4 sids 8220001-8220004): HTTP filename anchors for `praxisbackup.exe` and `dtest.dll`, SMB lateral delivery anchors for `Sysprox.sys` and `b.cache`.
- PEAK hunts (3): `peak_h1_safemode_boot_silent_reboot.md` — bcdedit safeboot + `\Safeboot\Network\` write + forced reboot without maintenance window; `peak_h2_byovd_unsigned_driver_load_burst.md` — kernel driver load outside `\System32\drivers\` plus AV process stop within 15 min; `peak_h3_debug_dir_rust_loader_landing_pad.md` — burst of canonical MDeployer filenames in `C:\Windows\Debug\`.
- `iocs.csv` (38 entries) — eight SHA1 sample anchors plus probmon.sys SHA256, mutex lyric strings, two hardcoded RC4 keys, MDeployer payload paths, registry persistence keys, service name rotations, and operator/victimology notes.
- `kill_chain.svg` — viewBox 880×1180, GitHub-friendly adaptive light/dark palette, eight numbered stages on victim host lane (PowerShell staging through Perf_sys task, MDeployer drops, Safe Mode Boot + irnagentd persistence, BYOVD probmon.sys, MS4Killer AV termination, discovery, encryption impact), operator/toolkit panel on right anchoring Rust toolkit + per-victim AV list + victimology, separate on-chain laundering panel (USD 34.2 M total, USD 13.5 M to VASPs, USD 1 M via Cryptex.net, USD 18.8 M parked), bidirectional yellow arrows on stages 3 and 5, purple arrow from impact to laundering panel, detection-anchors footer mapping every deliverable plus IR order-of-operations and three explicit DO-NOT directives.

### Pedagogy
- `T1562.009 Safe Mode Boot` is the cleanest 2026 evasion vector for ransomware — detection must live at the `\Safeboot\Network\<service>` registry write and at `bcdedit safeboot Minimal`, not at the encryption payload that runs in a defence-stripped host.
- BYOVD has become commoditised; track it by driver name, not by ransomware family — Embargo (`probmon.sys`) joins the existing repo catalogue and the LOLDrivers project is now a first-class detection-engineering dependency.
- Per-victim custom compile is the new normal — MS4Killer ships a superset of decoy AV process names and recompiles with the actual target subset, so YARA must anchor on compile-time invariants (RC4 keys, mutex lyric, minifilter API imports) rather than on the process list.
- BlackCat → Embargo rebrand is supported by Rust + leak-site + on-chain wallet overlap; apply the same multi-modal heuristic when triaging future rebrand claims.

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
- `days/2026-05-14_Mini-Shai-Hulud-TeamPCP-Mega-Campaign/` — TeamPCP supply-chain worm campaign that compromised 170+ npm/PyPI packages (404 malicious versions, 518M cumulative downloads affected) via a GitHub Actions `pull_request_target` Pwn Request against TanStack/router. The attacker fork `zblgg/configuration` opened a PR t