# PEAK H1 — JFMBackdoor side-load chain through fltMC.exe + FLTLIB.dll from %TEMP%

**Date:** 2026-05-22
**Author:** Jarmi
**Hypothesis class:** Hypothesis-driven (PEAK)
**Confidence:** high

## Hypothesis

A Windows endpoint in our estate has executed `fltMC.exe` from a user-writable
path between 2025-07-01 and now, side-loading an attacker-supplied `FLTLIB.dll`
that decrypts `scr.mui` with XOR key `Zs0@31=KDw.*7ev`, then loads the
`flt.bin` shellcode that maps the JFMBackdoor PE into memory and calls home to
`namefuture[.]site`, `cumm[.]info` or `xcent[.]online`. The host is operated
by Red Lamassu / Calypso APT against the telecommunications or government
sector in Asia.

## Why this discriminates

- The legitimate `fltMC.exe` is shipped in `C:\Windows\System32\` and is never
  copied elsewhere by default. Any execution from `%TEMP%`, `%ProgramData%`,
  `%AppData%` or `C:\Users\Public\` is the strongest anchor.
- The four staging artefacts (`FLTLIB.dll`, `flt.bin`, `scr.mui`, `fltMC.exe`)
  are downloaded together into the same folder — observing three of the four
  filenames co-located in `%TEMP%` is high-confidence evidence.
- The `1.bat` PowerShell stager uses `WindowStyle Hidden` + `Invoke-WebRequest`
  to pull from a single HTTP host on port 8000; the open-directory pattern is
  consistent across the campaign.

## Expected benign vs malicious

- Benign: legitimate Filter Manager management is performed only by SCCM, GPO
  or sysadmin scripts that invoke the System32 binary directly. Internal
  air-gapped installers that stage `fltMC.exe` exist but are rare and run
  under known service accounts.
- Malicious: a user account whose endpoint suddenly stages `FLTLIB.dll` next
  to a copied `fltMC.exe` in `%TEMP%`, with the four artefacts arriving within
  the same minute from a single remote host, followed by an `fltMC.exe`
  execution outside System32 and an HTTPS egress to a Cloudflare-fronted
  domain. The presence of `scr.mui` is a particularly strong anchor — the
  filename is real but the content is an encrypted Red Lamassu config blob.

## Action on match

1. Quarantine the host with EDR network isolation.
2. Pull `%TEMP%\flt.bin`, `%TEMP%\FLTLIB.dll`, `%TEMP%\scr.mui`,
   `%TEMP%\fltMC.exe` and `%TEMP%\1.bat` for forensic preservation.
3. Memory acquisition first — JFMBackdoor maps the final PE into memory only;
   the on-disk image is the shellcode loader (`flt.bin`).
4. Hunt across the estate for the same hash of `FLTLIB.dll` and the
   `Zs0@31=KDw.*7ev` XOR key as a YARA scan anchor on file shares.
5. Block the four PwC-published C2 domains at the egress proxy and the open
   directory host 23.27.201.160 in firewall logs back to 2025-07-01.

## Linked rules

- `sigma/jfmbackdoor_fltmc_sideload_fltlib_dll.yml`
- `sigma/jfmbackdoor_artifact_drop_temp_chain.yml`
- `kql/jfmbackdoor_fltmc_sideload_chain.kql`
- `yara/RedLamassu_JFMBackdoor_Showboat_2026.yar`
- `suricata/red_lamassu_2026_05.rules` (sids 8220005, 8220006)
