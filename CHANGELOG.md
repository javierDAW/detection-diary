# CHANGELOG

All notable additions to detection-diary.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is by date (`YYYY.MM.DD`) — every published case bumps the calendar version.

---

## 2026.05.09 — Day 13 — Albiriox Android MaaS RAT with AcVNC FLAG_SECURE bypass

### Added
- `days/2026-05-09_Albiriox-Android-MaaS-AcVNC/` — Cleafy Labs technical write-up of a Russian-speaking MaaS Android banking RAT priced at USD 650-720 per month that targets 400+ banking, fintech and cryptocurrency wallet apps worldwide. The novel primitive is **AcVNC** (Accessibility-VNC): the malicious AccessibilityService walks the live UI as `AccessibilityNodeInfo` JSON and streams it to the operator, which **bypasses Android's `FLAG_SECURE`** because the flag protects the framebuffer and `MediaProjection` but not the accessibility node tree. Delivery used a fake Penny Market dropper in the DACH region; iteration through Q1-Q2 2026 has expanded geography.
- Sigma (2): AccessibilityService binding to a non-store, non-system sideloaded package; default SMS handler change to a non-allowlist package.
- KQL (2): Defender XDR Mobile — sideload + accessibility within 24h on a banking-app device; Notification Listener + READ_SMS coexistence on a non-stock package.
- YARA (1): `Albiriox_Android_Banking_RAT_2026` — DEX magic at offset 0 + AccessibilityService + dispatchGesture + AccessibilityNodeInfo + getBoundsInScreen + TYPE_APPLICATION_OVERLAY + AcVNC marker (or blackscreen command) + AppInfos class + 2-of-N target package strings, capped at 50 MB.
- SPL (1): MTD CIM-normalised correlation (Lookout / Zimperium / Workspace ONE Intelligence) across install + accessibility + admin grant + SMS handler change in a 24h window per package per device.
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
- YARA (1): `CodeOfConduct_AiTM_PDF_Lure_202