# PEAK Hunt H1 — Dream Job PDF side-loading foothold

**Author:** Jarmi · **Date:** 2026-08-14 · **ATT&CK:** T1574.002 (DLL Side-Loading), T1204.002 (User Execution)

## Hypothesis
If a host was compromised through Lazarus' 2026 Operation Dream Job chain, then a legitimately-signed PDF/MuPDF viewer will have loaded a malicious `libmupdf.dll` from a user-writable path, and/or the trojanized `SecurityPDF.exe` viewer will be present on disk.

## Prepare
- Data sources: Sysmon EID 7 (image load) and EID 1 (process create); Defender XDR `DeviceImageLoadEvents`, `DeviceFileEvents`, `DeviceProcessEvents`.
- Scope: defense/aerospace endpoints, engineering and recruiter-facing users; last 90 days (zero-day active since early June 2026).
- Baseline: where does a legit `libmupdf.dll` live in your fleet (install directories under Program Files)?

## Execute
1. Image-loads of `libmupdf.dll` from `\Users\`, `\Downloads\`, `\Temp\`, or `\AppData\Local\Temp\` (see `kql/pdfviewer_sideload_libmupdf.kql`).
2. File writes of `libmupdf.dll` outside install directories; check the signature of the DLL and of the parent viewer.
3. Presence of `SecurityPDF.exe` on disk; PDFs containing the marker `This document is encrypted with sumatrapdf reader!!!!!!!!!!!!` (YARA `Lazarus_DreamJob_SecurityPDF_Marker`).
4. Match sample hashes from `iocs.csv` (DLL loader/dropper, PDF payload, SecurityPDF.exe).

## Act
- Confirmed side-load: isolate the host, pull memory (MISTPEN/Troy run in memory), pivot to H2 (kernel-integrity) and H3 (C2).
- Promote the strongest signals (unsigned `libmupdf.dll` next to a signed viewer; the marker string) to standing detections.

## Notes
The decoy is a real job description (e.g. fake Lockheed Martin); user reports of a "recruiter PDF that did nothing" are a strong pivot.
