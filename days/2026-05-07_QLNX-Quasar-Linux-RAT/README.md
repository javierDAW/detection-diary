---
date: 2026-05-07
title: "QLNX (Quasar Linux RAT) — Linux developer/DevOps implant with rootkit, PAM backdoor and supply-chain credential harvester"
clusters:
  - "QLNX"
  - "Quasar Linux"
cluster_country: "Unattributed (e-crime hypothesis — financially motivated supply-chain pre-position)"
techniques_enterprise:
  - T1190
  - T1027.004
  - T1059.004
  - T1546.004
  - T1547.013
  - T1053.003
  - T1556.003
  - T1574.006
  - T1014
  - T1480
  - T1083
  - T1552.001
  - T1555.005
  - T1614
  - T1071.001
  - T1573.002
  - T1041
  - T1070.004
  - T1564.001
  - T1195.001
  - T1195.002
platforms:
  - linux
  - supply-chain
sectors:
  - technology
  - software-development
  - cloud-multi
---

# QLNX — Quasar Linux RAT (Trend Micro, 5-may-2026)

**Cluster name (vendor):** *Quasar Linux* / **QLNX** — first public documentation by Trend Micro on **5-may-2026**. Confidence on attribution: **low** (no vendor links it to a known crew yet); strong fit with the **2026 supply-chain pre-position trend** that gave us LiteLLM (mar-2026), Telnyx (mar-2026), Bitwarden CLI / *Shai-Hulud: The Third Coming* (apr-2026) and *Mini Shai-Hulud* (apr-30-2026).

**Family:** Linux ELF RAT v**1.4.1**, single binary, in-memory, **58-command** C2 framework, custom TCP/TLS framing **+** HTTP/HTTPS fallback. Embeds C source for a **PAM backdoor** and an **LD_PRELOAD rootkit**, compiled **on the victim** with `gcc`. eBPF rootkit controller hides PIDs / files / ports from `ps`, `ls`, `netstat`. Detected by **only four AV engines** at publication time.

**Why this case for Thursday's supply-chain slot:** QLNX is *not* itself a malicious package — it is the **upstream cause** of supply-chain incidents like LiteLLM and Bitwarden CLI. It's the Linux foothold that lets the operator **publish trojanized npm/PyPI packages from a developer's account**. Defending the registry is necessary but insufficient if the developer's box is owned.

## Attribution and confidence

- Trend Micro names the family Quasar Linux / **QLNX**; the name does **not** imply a relationship with the legacy Windows Quasar RAT (open-source C# project popular since 2015). Naming overlap is coincidental.
- No public attribution to a state-nexus cluster as of 2026-05-07.
- Operational tradecraft (selection of credential targets, dynamic on-host compilation, eBPF kernel hiding, in-memory execution, log scrubbing) is **financially-motivated, supply-chain-oriented**.
- Genealogy: pattern is consistent with the **TeamPCP** style of *credential-first, package-publishing-second* attacks, but no shared infra has been published yet — treat as **independent until corroborated**.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Resource Dev | T1583 / T1588 | Distribution likely via trojanized dev tooling (Docker images, IDE extensions, npm postinstall) — vector still under investigation |
| Initial Access | T1190 / T1195.001 | Hypothesised: trojanized package or container image executed on dev/DevOps host |
| Execution | T1059.004, T1027.004 | Compiles its own PAM module + LD_PRELOAD shim with `gcc -shared -fPIC` from embedded C source strings |
| Persistence | T1574.006, T1546.004, T1547.013, T1053.003 | **Seven** anchors: `/etc/ld.so.preload`, systemd unit, crontab, `init.d`, XDG autostart, `.bashrc`/.zshrc, `/etc/profile.d` — all marked with `QLNX_MANAGED` |
| Privilege Escalation | (root required upstream) | Operator dependency — if implant lands as user, only the user-tier persistence anchors fire; full rootkit needs root |
| Defense Evasion | T1014, T1027, T1564.001, T1070.004 | LD_PRELOAD userspace rootkit + eBPF map-based kernel rootkit; in-memory exec; deletes own dropper from disk; wipes shell history and `wtmp/btmp`; spoofs process name |
| Credential Access | T1552.001, T1555.005, T1556.003 | Single-shot harvester for `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, `.vault-token`, GH CLI tokens; PAM backdoor logs **plaintext** credentials of every authentication |
| Discovery | T1083, T1614 | `/etc/machine-id`, MAC, hostname, IPs, geolocation via `ip-api.com` |
| Lateral Movement | T1021.004 | Silently logs outbound SSH session traffic from the host (PAM hook on `pam_get_authtok` + read-tap) |
| C2 | T1071.001, T1573.002 | Custom TCP framing over TLS; HTTP(S) fallback. Beacon contains version + OS + privilege + machine fingerprint + IP/UA |
| Collection / Exfil | T1041 | Credentials packaged as XOR-encrypted blob written to `/var/log/.ICE-unix/...` then exfiltrated over the C2 channel |
| Impact (intent) | (supply-chain pre-position) | Operator pivots from harvested registry tokens to **publish trojanized packages** on npm/PyPI under the victim's identity |

## Reverse-engineering anchors

- **Single-instance mutex:** the implant computes `DJB2("quasar_linux") = 0x752e2ca1` and creates `/tmp/.X752e2ca1-lock`, masquerading as an X11 lock.
- **Master password:** `O$$f$QtYJK` — accepted by the PAM backdoor as a universal bypass for any local account.
- **Marker:** every persistence artifact contains a comment line with the literal string `QLNX_MANAGED` — used by the implant for self-cleanup, used by us as a confirm-IOC.
- **C source strings:** `pam_get_authtok`, `la_objsearch` and the literal `-shared -fPIC` are embedded as ASCII string literals; the binary `popen()`s `gcc` and pipes the source through stdin to produce distro-matching `.so` files (no compile farm fingerprint, no static linkage to libpam).
- **Geolocation enrichment:** initial beacon includes geo retrieved from `ip-api.com` (free tier, no auth) — easy network anchor.
- **Detection coverage at publication:** ~4 vendors flag the binary; YARA-side anchors must be **structural + content** (markers, paths, master password, version), not signed.

## What's in this folder

| File | Purpose |
|---|---|
| [`README.md`](./README.md) | This document |
| [`sigma/qlnx_ld_so_preload_write.yml`](./sigma/qlnx_ld_so_preload_write.yml) | Write to `/etc/ld.so.preload` (file_event) |
| [`sigma/qlnx_pam_backdoor_drop.yml`](./sigma/qlnx_pam_backdoor_drop.yml) | Drop of `.so` under `/tmp` `/var/log/.ICE-unix` etc. |
| [`sigma/qlnx_gcc_compile_in_runtime_path.yml`](./sigma/qlnx_gcc_compile_in_runtime_path.yml) | gcc compiling `.so` under runtime/temp paths |
| [`sigma/qlnx_qlnx_managed_marker_in_persistence.yml`](./sigma/qlnx_qlnx_managed_marker_in_persistence.yml) | `QLNX_MANAGED` string in newly created persistence artifact |
| [`kql/qlnx_ld_preload_modification.kql`](./kql/qlnx_ld_preload_modification.kql) | Defender XDR — `DeviceFileEvents` on `/etc/ld.so.preload` |
| [`kql/qlnx_credential_files_burst.kql`](./kql/qlnx_credential_files_burst.kql) | Single process reads >=3 dev-credential files in 60s |
| [`kql/qlnx_ipapi_geo_beacon.kql`](./kql/qlnx_ipapi_geo_beacon.kql) | Outbound to `ip-api.com` from server tier |
| [`kql/qlnx_x11_lock_path_drop.kql`](./kql/qlnx_x11_lock_path_drop.kql) | Creation of `/tmp/.X<DJB2>-lock` |
| [`yara/QLNX_Quasar_Linux_RAT_2026.yar`](./yara/QLNX_Quasar_Linux_RAT_2026.yar) | Heuristic YARA over markers + paths + version |
| [`suricata/qlnx_ipapi_recon.rules`](./suricata/qlnx_ipapi_recon.rules) | Suricata 7.x — `ip-api.com` from server + custom-TCP beacon shape |
| [`hunts/peak_h1_qlnx_credential_burst.md`](./hunts/peak_h1_qlnx_credential_burst.md) | PEAK H1 — credential burst + geo recon |
| [`iocs.csv`](./iocs.csv) | Validated IOCs (paths, markers, master pw, version) |

## Sources

- [Trend Micro — Quasar Linux (QLNX): A Silent Foothold in the Software Supply Chain (5-may-2026)](https://www.trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html)
- [SecurityWeek — Sophisticated Quasar Linux RAT Targets Software Developers (5-may-2026)](https://www.securityweek.com/sophisticated-quasar-linux-rat-targets-software-developers/)
- [BleepingComputer — New stealthy Quasar Linux malware targets software developers (5-may-2026)](https://www.bleepingcomputer.com/news/security/new-stealthy-quasar-linux-malware-targets-software-developers/)
- [SOC Prime — Quasar Linux (QLNX): A Supply Chain Foothold with Full RAT Capabilities](https://socprime.com/active-threats/qlnx-linux-rat-uses-rootkit-and-pam-backdoor/)
- [MITRE ATT&CK — T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK — T1556.003 Modify Authentication Process: Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003/)
- [MITRE ATT&CK — T1552.001 Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)

— Jarmi
