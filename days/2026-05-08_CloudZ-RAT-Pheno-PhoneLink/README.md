---
date: 2026-05-08
title: "CloudZ RAT + Pheno plugin — Microsoft Phone Link SQLite OTP/SMS theft (Cisco Talos, May 2026)"
clusters:
  - "CloudZ"
  - "Pheno"
cluster_country: "unattributed (low confidence) — financially-motivated credential / OTP theft"
techniques_enterprise:
  - T1566
  - T1036.005
  - T1204.002
  - T1059.001
  - T1053.005
  - T1027.002
  - T1497.003
  - T1622
  - T1518.001
  - T1027.011
  - T1539
  - T1111
  - T1056.001
  - T1115
  - T1213
  - T1005
  - T1071.001
  - T1102.002
  - T1090.004
  - T1573.002
  - T1041
techniques_ics: []
platforms:
  - windows
sectors:
  - any
---

# CloudZ RAT + Pheno plugin — Microsoft Phone Link SQLite OTP/SMS theft (Cisco Talos, May 2026)

## TL;DR

Cisco Talos disclosed on 5 May 2026 a modular .NET RAT called **CloudZ** (ConfuserEx-packed, compile timestamp 13 January 2026) and an OTP-focused plugin called **Pheno** that abuses **Microsoft Phone Link**'s default SMS-mirroring behaviour to steal 2FA codes **at user level on the PC, without touching the paired phone**. CloudZ enters as a fake **ScreenConnect installer** (Rust dropper), unpacks a .NET loader that runs a three-step anti-analysis chain (sleep-skew sandbox detection, forensic-tool enumeration, `_ENABLE_PROFILING` probe), and `Assembly.Load`s CloudZ into memory. CloudZ uses `System.Reflection.Emit.DynamicMethod` + `ILGenerator` to **construct methods at runtime**, so the actual logic does not appear in the on-disk assembly's method tables — defeating static decompilers. Pheno is downloaded on demand, scans for `YourPhone.exe`, `PhoneExperienceHost.exe` and the `Link to Windows` companion, then opens `%LOCALAPPDATA%\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences-*.db` with the embedded `Microsoft.Data.Sqlite` and filters for OTP-shaped numeric tokens. C2 is a Cloudflare Workers + Pastebin fabric: `*.hellohiall.workers.dev`, Pastebin handle `HELLOHIALL`, backend IP `185.196.10.136`. Campaign activity reaches back at least to **January 2026** — more than four months of dwell time at publication. Attribution is **low** — no named cluster as of 2026-05-07. The defender takeaway is structural: **SMS-based 2FA is broken by Windows 11's mirroring design, not by an attacker's novel capability**. Migrate to FIDO2 / passkey; in the meantime, hunt for non-YourPhone processes that read the `PhoneExperiences-*.db` SQLite.

## Attribution and confidence

- **Family (Talos):** **CloudZ** (.NET RAT) and **Pheno** (Phone Link OTP plugin). Vendor-assigned names, unique to this report.
- **Attribution:** **low**. No public link to a named state-nexus or e-crime cluster as of 2026-05-07. Tradecraft (fake ScreenConnect lure, Cloudflare Workers + Pastebin C2, IL-emit fileless logic) is consistent with **commodity .NET RATs evolving toward token / OTP theft**, but no shared infrastructure has been published with adjacent families.
- **Vendor that discovered:** Cisco Talos (primary disclosure 5 May 2026). Secondary coverage: BleepingComputer, The Hacker News, Dark Reading. Cisco's IOC repository on GitHub mirrors the technical anchors.
- **Confidence:**
  - **high** on the technical attribution to the CloudZ + Pheno family — Talos captured the binaries and the SQLite-read primitive at byte level.
  - **low** on operator identity.
- **Victimology:** sector-incidental; anyone running Windows 11 with Phone Link bound to a phone, with SMS 2FA on relevant accounts. Phone Link is **enabled by default** in modern Windows 11 deployments, so the victim pool is the size of the Windows 11 user base.
- **Genealogy / link with previous repo cases:** none direct. Conceptually adjacent to Day 13 (Albiriox) — both attacks aim at SMS / OTP-class second factors; Albiriox from the device side via Android Accessibility, CloudZ + Pheno from the network side via the PC's mirrored SQLite. The shared pedagogical anchor is **FIDO2 / passkey as the only durable second factor in 2026**.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Initial Access | T1566 | Delivery vector unconfirmed; first observed artefact is a fake **ScreenConnect update** executable |
| Execution | T1204.002, T1059.001 | User runs the fake update; downstream RAT executes `cmd` / `powershell` on demand |
| Defense Evasion (delivery) | T1036.005 | Binary masquerades as legitimate ScreenConnect installer |
| Persistence | T1053.005 | Scheduled task (logon / boot trigger) executes the .NET loader from `%APPDATA%\<random>\` |
| Defense Evasion (loader) | T1027.002, T1497.003, T1622, T1518.001 | ConfuserEx packing; sleep-skew sandbox check; `_ENABLE_PROFILING` debugger probe; forensic-tool process enumeration |
| Defense Evasion (runtime) | T1027.011 | CloudZ uses `System.Reflection.Emit.DynamicMethod` + `ILGenerator` to build methods at runtime |
| Credential Access | T1539, T1111, T1056.001, T1115 | Browser cookies / credentials; **Phone Link SQLite read for SMS / OTP**; keylogging; clipboard monitor |
| Collection | T1213, T1005 | Local SQLite harvest; arbitrary file download |
| Command and Control | T1071.001, T1102.002, T1090.004, T1573.002 | HTTPS to Cloudflare Workers (`*.hellohiall.workers.dev`); Pastebin dead-drop (`HELLOHIALL`); custom encrypted socket to backend IP |
| Exfiltration | T1041 | Over the C2 channel |

![CloudZ + Pheno kill chain](./kill_chain.svg)

The diagram has the victim Windows 11 host on the left lane and the C2 fabric (Cloudflare Workers + Pastebin dead-drop + backend IP) on the right lane. The most operationally important stage is **Pheno reading the YourPhone SQLite at user level** — no SYSTEM, no driver, no kernel hook needed — which is the design-side break of SMS-based 2FA. Detection anchors at the bottom map to the two Sigma rules (Phone Link SQLite read by foreign process; AppData parent → `schtasks /create` loader persistence), two KQL rules (Phone Link DB read joined with Workers egress in 30 min; Pastebin raw fetch + Workers egress same host), the YARA rule on CloudZ / Pheno heuristic and the Suricata rule on the Workers SNI / Pastebin path / backend IP.

## Stage-by-stage detail

### Initial Access — fake ScreenConnect update

A Rust-compiled dropper masquerading as a ScreenConnect installer drops the .NET loader and registers persistence. Public SHA-256 of the dropper variant captured by Talos: `65fcd965040fabeb6f092df0a4b6856125018bb3b6a1876342da458139f77dac`. The delivery vector itself (email link, drive-by, search ad poisoning) is not confirmed in the Talos write-up; the dropper is the first observed artefact. MITRE: `T1566`, `T1036.005`.

### Execution + Persistence

The dropper writes the .NET loader into `%APPDATA%\<random>\` and registers a scheduled task with logon and boot triggers pointing at the loader. The scheduled-task name is randomised per build — there is no fixed naming anchor. Sigma in this folder anchors on the **AppData-parent → `schtasks /create` chain**, which is the durable signal regardless of the loader's filename. MITRE: `T1204.002`, `T1059.001`, `T1053.005`.

### Defense Evasion — loader anti-analysis chain

The loader (variants `ed5de036...3832`, `24398b75...b2b2c`) runs three pre-unpacking checks:

1. **Sleep-skew detection.** Calls `Thread.Sleep(N)` and measures wall-clock with `Stopwatch`. If the elapsed time is materially less than `N`, the loader assumes a sandbox is fast-forwarding sleeps and exits.
2. **Forensic-tool enumeration.** Iterates `Process.GetProcesses()` and matches against `wireshark`, `fiddler`, `procmon`, `sysmon`, `processhacker`, `x64dbg`, `ollydbg`, `dnspy`, `dnspyex`, `ida`, `ida64`. Hit → silent exit.
3. **Profiler / debugger probe.** Reads the `_ENABLE_PROFILING` environment variable (set by .NET when a profiler is attached). Present → exit.

Only after all three checks pass does it `Assembly.Load` the decrypted CloudZ payload and invoke its entry point. MITRE: `T1027.002`, `T1497.003`, `T1622`, `T1518.001`.

### CloudZ RAT — modular .NET implant with IL emit

- **Compile timestamp:** 2026-01-13.
- **Packer:** ConfuserEx.
- **Code generation:** uses `System.Reflection.Emit.DynamicMethod` with `ILGenerator` to construct methods at runtime — defeats static decompilers (the actual logic does not appear in the on-disk assembly's method tables). MITRE: `T1027.011`.
- **Capabilities:** keylogging, clipboard monitor, file management (delete, download, write), arbitrary command execution, browser data theft.
- **Configuration:** decrypts a local stub at start; pulls additional config from Pastebin pages tagged with handle `HELLOHIALL`; refreshes endpoints from Cloudflare Workers URLs.
- **Transport:** custom encrypted socket to backend IP `185.196.10.136`; HTTP / HTTPS fallback to `*.hellohiall.workers.dev`.

### Pheno plugin — Phone Link SQLite OTP harvest

Downloaded on demand from `hxxps://orange-cell-1353.hellohiall.workers.dev/pheno.exe` (SHA-256 `33af554562176eff34598a839051b8e91692b0305edfdbb4d8eb9df0103ffd98`).

Pheno keeps a process-name watch loop for the *YourPhone* UWP package — `YourPhone.exe`, `PhoneExperienceHost.exe` and the mobile companion `Link to Windows`. When an active PC-to-phone bridge is observed, Pheno reads:

```
%LOCALAPPDATA%\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences-*.db
```

This SQLite file caches messages and notifications mirrored from the paired phone, including SMS bodies and (depending on the user's mirroring choices) push-notification content from authenticator-class apps. Pheno opens the DB with embedded `Microsoft.Data.Sqlite`, filters for OTP-shaped numeric tokens and known service strings (`code`, `verification`, `otp`, `token`, `Microsoft`, `Apple`, `Google`, `Meta`, banking-vendor names) and exfiltrates the matching rows. MITRE: `T1111`, `T1213`, `T1539`.

The harvest runs entirely **at user level** — no driver, no SYSTEM token, no kernel hook needed. The novelty is not technical sophistication; it is the **choice of target**.

### Command and Control

Three transports stacked:

- **Cloudflare Workers** (`*.hellohiall.workers.dev`) — primary HTTPS C2; rotates subdomains without rebuilding the binary.
- **Pastebin dead-drop** (handle `HELLOHIALL`) — config and updated endpoint refresh; HTTP GET on `pastebin.com/raw/*`.
- **Custom encrypted socket to backend IP `185.196.10.136`** — direct fallback when the Workers path is blocked.

MITRE: `T1071.001`, `T1102.002`, `T1090.004`, `T1573.002`.

### Exfiltration

All captured material — OTPs, SMS bodies, browser cookies, clipboard contents, keystrokes — is exfiltrated over the C2 channel. MITRE: `T1041`.

## RE notes

| Component | SHA-256 | Lang / build | Notes |
|---|---|---|---|
| Dropper (fake ScreenConnect update) | `65fcd965040fabeb6f092df0a4b6856125018bb3b6a1876342da458139f77dac` | Rust | Masquerades as installer; drops .NET loader |
| .NET loader (variant 1) | `ed5de036...3832` | C# / ConfuserEx | Sleep-skew + tool enum + profiler probe |
| .NET loader (variant 2) | `24398b75...b2b2c` | C# / ConfuserEx | Same chain, rebuilt |
| CloudZ RAT | not published byte-stable | C# / ConfuserEx | Runtime IL emit; loaded in-memory |
| Pheno plugin | `33af554562176eff34598a839051b8e91692b0305edfdbb4d8eb9df0103ffd98` | C# | Phone Link SQLite read; OTP regex; embedded `Microsoft.Data.Sqlite` |

Operational reverser pointers:

- **ConfuserEx removal**: standard `de4dot` / `ConfuserEx Unpacker` rounds, then expect to encounter the dynamic IL emit layer. Decompiled output will look like a "method factory" emitting opcodes from a `byte[]`.
- **To reconstruct dynamic methods at runtime**, attach a managed debugger (dnSpyEx) to a running CloudZ instance, set a breakpoint on `DynamicMethod.Invoke` or `DynamicMethod.CreateDelegate`, and dump the generated IL. Alternatively, capture `Microsoft-Windows-DotNETRuntime` ETW events `MethodLoadVerbose` and `MethodILToNativeMap` with `dotnet-trace collect`.
- **Pheno is small and not heavily packed**; static analysis with dnSpyEx is sufficient to confirm Phone Link string anchors, the `Microsoft.Data.Sqlite` reference and the OTP-keyword regex set.
- **The `hellohiall.workers.dev` parent zone** is the cleanest network anchor. Blocking `*.workers.dev` outright is operationally infeasible (collateral damage); blocking `*.hellohiall.workers.dev` is cheap and decisive.

## Detection strategy

### Telemetry that matters

- **Sysmon EID 11** (`file_event`) for any non-YourPhone process opening `Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences*.db`.
- **Sysmon EID 1** (`process_creation`) for `schtasks /create` with a `/TR` argument pointing into `%APPDATA%`; for fake-update binaries running out of `%APPDATA%` or `%TEMP%`.
- **Sysmon EID 3** (`network_connection`) for outbound to `*.hellohiall.workers.dev`, to `185.196.10.136`, and for `pastebin.com/raw/*` HTTP GETs from a non-developer host.
- **`Microsoft-Windows-DotNETRuntime` ETW** (`MethodLoadVerbose`, `MethodILToNativeMap`) for runtime IL emit telemetry where you have the EDR coverage to capture it.
- **Defender XDR `DeviceFileEvents`** + `DeviceNetworkEvents` correlation — the KQL rule joins the DB-read event with the Workers / backend-IP egress within a 30-minute window on the same host.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [`sigma/cloudz_phone_link_db_access.yml`](./sigma/cloudz_phone_link_db_access.yml) | Non-YourPhone process reads `PhoneExperiences-*.db` |
| Sigma | [`sigma/cloudz_dropper_schtasks_appdata.yml`](./sigma/cloudz_dropper_schtasks_appdata.yml) | AppData parent → `schtasks /create` chain |
| KQL (Defender XDR) | [`kql/cloudz_phone_db_to_workers_correlation.kql`](./kql/cloudz_phone_db_to_workers_correlation.kql) | Phone Link DB read joined with `*.hellohiall.workers.dev` or `185.196.10.136` egress within 30 min same host |
| KQL | [`kql/cloudz_pastebin_handle_hellohiall.kql`](./kql/cloudz_pastebin_handle_hellohiall.kql) | Pastebin raw fetch + Workers egress same host within a short window |
| YARA | [`yara/cloudz_pheno_heuristic.yar`](./yara/cloudz_pheno_heuristic.yar) | PE + ConfuserEx + Phone Link package strings + Workers FQDN + IL emit primitives + SQLite client |
| Suricata | [`suricata/cloudz_workers_pastebin.rules`](./suricata/cloudz_workers_pastebin.rules) | sids — TLS SNI / DNS / HTTP host `*.hellohiall.workers.dev` + IP egress `185.196.10.136` + Pastebin raw paths |
| Hunt | [`hunts/peak_h1_phone_db_then_workers.md`](./hunts/peak_h1_phone_db_then_workers.md) | PEAK H1 — Phone Link DB read followed by Workers / backend egress within 30 min |

### Threat hunting hypotheses

- **H1 — Phone Link DB read followed by Workers / backend egress in 30 minutes.** A non-YourPhone process touches `PhoneExperiences-*.db` and the same host beacons to `*.hellohiall.workers.dev` or `185.196.10.136` within 30 minutes. Expected benign: zero — the only legitimate reader of that SQLite is the YourPhone package itself. The detection-side join is the canonical anchor for this family.
- **H2 — `_ENABLE_PROFILING` probe + sleep-skew test from an AppData binary.** Behavioural anchor for the loader. The probe is itself unusual outside .NET developer telemetry; combine with a `Thread.Sleep` followed by `Stopwatch.Elapsed` instrumentation if your EDR provides .NET-class telemetry.
- **H3 — Pastebin raw fetch from a non-developer host + Workers egress same host.** Many environments do not see `pastebin.com/raw/*` on non-developer endpoints. Combine the GET with the Workers SNI to halve the false-positive rate.

## Incident response playbook

### First 60 minutes (triage)

1. **Isolate the host at the switch / EDR.** Do not power off — capture RAM first.
2. **Capture RAM** with WinPMem / DumpIt — the CloudZ IL emit lives in `clr.dll`-managed heap memory; static analysis of the on-disk binary alone misses the actual logic.
3. **Block egress** to `*.hellohiall.workers.dev` + `185.196.10.136` at the perimeter, and DNS sinkhole `hellohiall.workers.dev`.
4. **Inventory the user's 2FA accounts** — every service the user has SMS-2FA bound to is presumed compromised. Migrate to FIDO2 / passkey before re-enabling.
5. **Revoke active sessions and refresh tokens** on every cloud service tied to the user's identity. Password change alone is insufficient — captured OTPs let the operator complete 2FA again on the new password.
6. **Pull the scheduled task** the loader installed (`schtasks /query /v /fo list`) and the `%APPDATA%\<random>\` directory contents.
7. **Re-image the host.** ConfuserEx + runtime IL emit + scheduled-task persistence + possible browser cred theft makes clean-as-you-go unreliable.

### Artifacts to collect

| Artifact | Path | Tool | Why it matters |
|---|---|---|---|
| Full memory dump | host RAM | WinPMem / DumpIt | CloudZ IL-emit methods live only in memory |
| Phone Link SQLite | `%LOCALAPPDATA%\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences-*.db` | manual | Confirms what could have been read by Pheno |
| Scheduled task | `C:\Windows\System32\Tasks\<task>` + `schtasks /query /xml` | manual | Persistence anchor and command-line |
| Loader binary | `%APPDATA%\<random>\loader.exe` | manual | SHA-256 for IR evidence |
| Pheno plugin | `%APPDATA%\<random>\pheno.exe` | manual | SHA-256 for IR evidence |
| Sysmon log | `%windir%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | EvtxECmd | EID 1 / 3 / 11 — file read, schtasks, Workers egress |
| Defender / EDR telemetry | tenant | KQL export | DB read + network egress correlation |
| Prefetch | `C:\Windows\Prefetch\*.pf` | PECmd | Evidence-of-execution for the loader + Pheno |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | AmcacheParser | First-seen SHA1 + path |
| Browser data | per-browser cache / cookie store | manual | Confirms what cookies / sessions were touched |

### IR queries and commands

```cmd
:: Pull the scheduled task that ran the loader
schtasks /query /v /fo list | findstr /i "\\AppData\\"

:: Inspect the random loader directory
dir /A "%APPDATA%\" /S | findstr /i "\.exe \.dll \.dat"

:: Hash candidate binaries
certutil -hashfile "%APPDATA%\<random>\<file>.exe" SHA256
```

```kql
// Defender XDR — Phone Link DB read joined to Workers / backend egress within 30 min
let dbReads =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has @"Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\"
    | where FileName matches regex @"PhoneExperiences-.*\.db$"
    | where InitiatingProcessFileName !in~ ("YourPhone.exe", "PhoneExperienceHost.exe")
    | project ReadTime = Timestamp, DeviceId, DeviceName, AccountName,
              InitiatingProcessFileName, InitiatingProcessId, FolderPath, FileName;
let egress =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has "hellohiall.workers.dev" or RemoteIP == "185.196.10.136"
    | project EgressTime = Timestamp, DeviceId, InitiatingProcessId,
              RemoteUrl, RemoteIP, RemotePort;
dbReads
| join kind=inner egress on DeviceId, InitiatingProcessId
| where EgressTime between (ReadTime .. ReadTime + 30m)
| project ReadTime, EgressTime, DeviceName, AccountName,
          InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
```

```bash
# Volatility 3 on the captured RAM image — find managed methods emitted at runtime
vol -f mem.raw windows.netscan.NetScan | grep -E '185\.196\.10\.136|hellohiall|pastebin'
vol -f mem.raw windows.malfind.Malfind
vol -f mem.raw windows.dlllist.DllList | grep -E 'Microsoft\.Data\.Sqlite|System\.Reflection\.Emit'
```

### Containment, eradication, recovery

- **Containment.** Isolate the host; block the C2 fabric; revoke active sessions and refresh tokens for every cloud account the user is bound to; suspend the user temporarily and reset password from a different host.
- **Eradication.** Re-image the host. ConfuserEx + IL emit + scheduled task + possible browser cred theft means clean-as-you-go is unreliable. Reinstall the OS on the same hardware (or replacement hardware if firmware is suspect).
- **Recovery.** Migrate the user off SMS-based 2FA onto FIDO2 / passkey **before** re-enabling identity. Revoke and reseed any TOTP factor that was visible in the foreground during the dwell window. Audit financial accounts and Microsoft / Apple / Google / Meta / banking accounts for any anomalous activity in the dwell window.
- **What NOT to do.**
  - Do not power off before RAM capture — CloudZ IL emit is only in memory.
  - Do not stop at a password reset. OTPs captured during the dwell window let the operator complete 2FA again.
  - Do not trust on-host static AV for confirmation — IL emit defeats most static analysis.
  - Do not bring the user back online with SMS-2FA on the same accounts. Migrate to FIDO2 first.

### Recovery validation

- The host has been re-imaged with a clean OS install.
- The user is enrolled on FIDO2 / passkey for every service the operator could have phished or read OTPs from.
- 14 days without any process on the fleet reading `PhoneExperiences-*.db` from a non-YourPhone parent.
- 14 days without DNS or HTTP egress to `*.hellohiall.workers.dev` or `185.196.10.136` from any host.
- Active sessions and refresh tokens are confirmed revoked in the user's IdP.

## IOCs

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| sha256 | `65fcd965040fabeb6f092df0a4b6856125018bb3b6a1876342da458139f77dac` | Dropper (fake ScreenConnect update) | high | Cisco Talos |
| sha256 | `33af554562176eff34598a839051b8e91692b0305edfdbb4d8eb9df0103ffd98` | Pheno plugin | high | Cisco Talos |
| sha256 | `ed5de036...3832` (truncated) | .NET loader variant 1 | medium | Cisco Talos |
| sha256 | `24398b75...b2b2c` (truncated) | .NET loader variant 2 | medium | Cisco Talos |
| domain | `*.hellohiall.workers.dev` | Cloudflare Workers C2 parent | high | Cisco Talos |
| domain | `orange-cell-1353.hellohiall.workers.dev` | Pheno download URL host | high | Cisco Talos |
| ipv4 | `185.196.10.136` | Backend IP for custom encrypted socket | high | Cisco Talos |
| pastebin | `HELLOHIALL` | Pastebin handle for config / endpoint refresh | high | Cisco Talos |
| filepath | `%LOCALAPPDATA%\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences-*.db` | Phone Link SQLite read by Pheno | high | Cisco Talos |
| string | `Microsoft.Data.Sqlite` | Embedded SQLite client in Pheno | medium | Cisco Talos |
| string | `_ENABLE_PROFILING` | Anti-analysis profiler-probe env var | medium | Cisco Talos |
| ttp | `System.Reflection.Emit.DynamicMethod` + `ILGenerator` runtime method build | T1027.011 fileless on method level | high | Cisco Talos |
| ttp | AppData parent → `schtasks /create` chain | Loader persistence | high | Cisco Talos |
| compile_ts | 2026-01-13 | CloudZ compile timestamp | high | Cisco Talos |

Full list lives in [`iocs.csv`](./iocs.csv).

## Secondary findings

- **CVE-2026-6973 — Ivanti EPMM Improper Input Validation.** CISA KEV added 7 May 2026; actively exploited; FCEB deadline issued. Internal pentesters using EPMM should validate patch posture this week. Pivot risk for the broader fleet if any EPMM deployment is in scope.
- **DAEMON Tools Lite supply-chain trojanised.** Disc Soft confirms compromise of the installer and publishes a clean version (~6 May 2026, BleepingComputer). Review dev-station and lab-host inventories that installed DAEMON Tools in the last 8 weeks.
- **PCPJack.** New cloud-credential-stealing framework that **ejects TeamPCP from compromised hosts** (BleepingComputer ~7 May 2026). Inter-actor rivalry in the supply-chain space is now operationally measurable — monitor as a trend for 2026.

## Pedagogical anchors

- **SMS-based 2FA assumes the SMS lives on a separate device.** Windows 11 Phone Link breaks that assumption by design. Any user-context implant can read the mirrored SQLite.
- **Detection is on the file-event side, not the process-name side.** CloudZ is fileless on the method level (IL emit) — heuristic byte signatures are weak. The cheap, durable detection is *who reads the SQLite* (allowlist the YourPhone package) and *who beacons to `*.hellohiall.workers.dev`*.
- **Cloudflare Workers + Pastebin** is a low-cost, high-resilience C2 fabric: defenders rarely block `*.workers.dev` outright (collateral damage), Pastebin is often allow-listed, and the operator can rotate hostnames without rebuilding the binary. Block the *parent zone* `hellohiall.workers.dev`, not the wildcard.
- **Recovery requires more than a password reset.** Sessions and 2FA recovery codes captured during the dwell window remain valid. After IR, revoke device tokens, rotate every code that may have been mirrored to the host, and migrate to FIDO2 / passkey.
- **The novelty is not the malware — it is the target.** A defender that has been ignoring `PhoneExperiences-*.db` because it is "just a phone mirror" is now compromised at no extra cost to the operator.

## What's in this folder

| File | Purpose |
|---|---|
| [`README.md`](./README.md) | This case write-up |
| [`kill_chain.svg`](./kill_chain.svg) | CloudZ + Pheno kill-chain diagram, light / dark adaptive |
| [`iocs.csv`](./iocs.csv) | Machine-readable IOC list |
| [`sigma/cloudz_phone_link_db_access.yml`](./sigma/cloudz_phone_link_db_access.yml) | Sigma — non-YourPhone process reads `PhoneExperiences-*.db` |
| [`sigma/cloudz_dropper_schtasks_appdata.yml`](./sigma/cloudz_dropper_schtasks_appdata.yml) | Sigma — AppData parent → `schtasks /create` chain |
| [`kql/cloudz_phone_db_to_workers_correlation.kql`](./kql/cloudz_phone_db_to_workers_correlation.kql) | KQL — Phone Link DB read joined with Workers egress within 30 min |
| [`kql/cloudz_pastebin_handle_hellohiall.kql`](./kql/cloudz_pastebin_handle_hellohiall.kql) | KQL — Pastebin raw fetch + Workers egress same host |
| [`yara/cloudz_pheno_heuristic.yar`](./yara/cloudz_pheno_heuristic.yar) | YARA — CloudZ / Pheno heuristic (ConfuserEx + Phone Link + Workers + IL emit + SQLite) |
| [`suricata/cloudz_workers_pastebin.rules`](./suricata/cloudz_workers_pastebin.rules) | Suricata 7.x — TLS SNI / DNS / HTTP host / IP egress for the C2 footprint |
| [`hunts/peak_h1_phone_db_then_workers.md`](./hunts/peak_h1_phone_db_then_workers.md) | PEAK H1 — Phone Link DB read → Workers / backend egress within 30 min |

## Sources

- [Cisco Talos — CloudZ RAT potentially steals OTP messages using Pheno plugin (5 May 2026)](https://blog.talosintelligence.com/cloudz-pheno-infostealer/)
- [Cisco-Talos/IOCs — cloudz-pheno-infostealer.txt](https://github.com/Cisco-Talos/IOCs/blob/main/2026/05/cloudz-pheno-infostealer.txt)
- [BleepingComputer — CloudZ malware abuses Microsoft Phone Link to steal SMS and OTPs](https://www.bleepingcomputer.com/news/security/cloudz-malware-abuses-microsoft-phone-link-to-steal-sms-and-otps/)
- [The Hacker News — Windows Phone Link Exploited by CloudZ RAT to Steal Credentials and OTPs](https://thehackernews.com/2026/05/windows-phone-link-exploited-by-cloudz.html)
- [Dark Reading — Attacks Abuse Windows Phone Link to Steal 2FA codes](https://www.darkreading.com/threat-intelligence/attacks-abuse-windows-phone-link-2fa)
- [Microsoft Learn — Phone Link mirroring architecture](https://learn.microsoft.com/en-us/windows/phone-link/)
- [MITRE ATT&CK — T1027.011 Fileless Storage](https://attack.mitre.org/techniques/T1027/011/)
- [MITRE ATT&CK — T1111 Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/)
- [MITRE ATT&CK — T1102.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
