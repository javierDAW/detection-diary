# PEAK hunt H1 - SilentDelivery fake Chrome certificate error, CertFixer.msi and the ftp.exe RAR / LNK chain

## Prepare

- **Hypothesis:** a user browsing a compromised (watering-hole) site was shown a jsjiami-obfuscated fake Chrome SSL error with an "Install certificate" button, downloaded and ran a fake "Certificate Fix" utility (`CertFixer.msi`) that dropped the SquadC loader or SparrowDoor; or an Indonesian user opened `Strategi_AS_Referensi_April2026.rar` and double-clicked `Strategi_AS_Referensi_April2026.docx.lnk`, which abused `ftp.exe` to run `_rels/info.dll` (a batch script), expand `_rels/.rels.log` (CAB with the SquadC loader) and open the empty decoy `_rels/557.pdf`. SquadC then persisted under a registry value named `WindowsUpdateAssist`.
- **Why:** Check Point Research (2026-11-10) tracks SilentDelivery as one of three clusters of CopperDragon, a possible "digital quartermaster" supplying China-nexus actors (FamousSparrow, Earth Estries, Tropic Trooper, UAT-9244). The browser path needs no exploit - only a user who trusts a certificate prompt - so browser and MSI telemetry are the earliest anchors. SquadC only runs if a browser process (`chrome.exe`, `msedge.exe`, `edge.exe`, `firefox.exe`, `brave.exe`) exists, a sandbox-evasion check worth remembering when detonating samples.
- **Honesty:** roughly 40 percent of the Check Point report was read only through a model summary; hashes, domains and IPs carry medium confidence. The exact LNK command line, the SquadC install folder, the host EXE that side-loads `MSVCR110.dll` / `dtfbase.dll` / `WTSAPI32.dll` and the exact registry key holding `WindowsUpdateAssist` (Run is the common reading) are not published. No first-hand sample analysis. Indicators decay.
- **Scope:** 30 days of Defender XDR process, file, image-load, registry and network telemetry on Windows endpoints, 90 days of proxy / DNS; prioritise government and policy staff in Indonesia and Southeast Asia, and anyone who reported a "certificate error" on an otherwise trusted site.
- **Confidence:** high for `ftp.exe` with `_rels` / `info.dll` / `Strategi_AS_` arguments and for the `WindowsUpdateAssist` value; medium for the `CertFixer.msi` hashes and domains; low for the generic JS C2 URI paths.

## Execute

**Data sources / content:** `sigma/01_copperdragon_silentdelivery_ftp_exe_rar_lnk_chain.yml`, `sigma/05_copperdragon_squadc_windowsupdateassist_run_value.yml`, `kql/k1_mde_silentdelivery_ftp_exe_lnk_and_certfixer_msi.kql`, `kql/k2_mde_campaign_domains_and_ips_90d.kql`, `suricata/copperdragon_infrastructure.rules` (sids 9995001, 9995002, 9995004, 9995005), `yara/copperdragon_sparrow_artifacts.yar` (rules `CopperDragon_SilentDelivery_JS_Injector_C2_Paths`, `CopperDragon_Windows_Tooling_Strings`).

1. Run k1; baseline every `ftp.exe` execution (rare on modern endpoints) and every MSI whose name or hash matches `CertFixer`; review any `WindowsUpdateAssist` value.
2. Run k2 and the Suricata rules over 90 days; any contact with `microsfot[.]vip`, `microscoft[.]vip`, `aistei[.]com`, `astorialaza[.]com` or the shared certificate SHA-1 `760be920fad07881b8ce9d94e074a35b4f806717` scopes the hunt to those hosts.
3. In proxy logs, look for the injector beacon pattern: repeated `GET /image-check?t=<datetime>` polling, a `POST /report-url` with a JSON body holding the visited page URL, then a `/register-ip` call from a non-browser process shortly after an MSI install.
4. On candidate hosts, enumerate persistence and staging files:

```powershell
# Author: Jarmi
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
  $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).WindowsUpdateAssist
  if ($v) { [pscustomobject]@{ Key=$k; Data=$v } }
}
Get-ChildItem -Path C:\Users -Recurse -Force -Include 'CertFixer*','Strategi_AS_*','info.dll','.rels.log','557.pdf' -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTime, LastWriteTime
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; StartTime=(Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Cert' } | Select-Object TimeCreated, Id, Message
```

5. Pull browser history / cache for the visited compromised site (the `/report-url` body names it) and scan cached scripts and the MSI payloads with YARA:

```bash
# Author: Jarmi
yara -s yara/copperdragon_sparrow_artifacts.yar /evidence/<host>/Users/
```

## Act

- **Findings handling:** per host: the compromised site that served the fake error, MSI name and SHA256, install time, `WindowsUpdateAssist` data path, side-loaded DLL and its host EXE, first and last C2 contact.
- **Escalation:** a confirmed CertFixer install or ftp.exe `_rels` chain = active CopperDragon intrusion. Isolate the host, collect the MSI, the loader folder and memory before cleanup, and pivot to H2 / H3 (follow-on SparrowDoor, credential theft, lateral movement). Notify the owner of the compromised website (watering hole) through CERT channels.
- **Detections:** promote Sigma 01 and 05 to production; consider WDAC / ASR rules that block `ftp.exe` and MSI installs launched from browser download folders for non-admin users; teach users that a browser never asks them to install a "certificate fix" executable.
- **Exit criteria:** every CertFixer / ftp.exe hit explained; no `WindowsUpdateAssist` values left; no traffic to the SilentDelivery domains, IPs or the shared certificate.
- **Caveat:** lure names, MSI names and domains rotate; the durable signals are a browser-delivered MSI followed by DLL side-loading and a new autostart value, and ftp.exe executing a script from an archive folder.
