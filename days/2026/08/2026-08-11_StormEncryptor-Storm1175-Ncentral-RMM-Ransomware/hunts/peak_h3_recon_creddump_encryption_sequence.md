# PEAK Hunt H3 - Rapid recon to credential dump to encryption

## Hypothesis
Microsoft notes Storm-1175 moves from initial access to exfiltration and encryption within days. If
an intrusion is mid-chain we expect, on one or a few hosts, a compressed sequence: Advanced IP
Scanner discovery, AnyDesk/SimpleHelp remote access, Mimikatz LSASS credential theft, then a burst
of `.encrypted` renames and `!!!README_FIRST!!!.txt` notes.

## Rationale (ABLE)
- **Actor behaviour:** high-tempo hands-on-keyboard operation - discover, harvest credentials,
  stage/exfiltrate, then deploy the locker across reachable shares.
- **Analytic value:** each step is individually noisy, but the ordered co-occurrence on the same
  host/subnet over a short window is high-fidelity and gives lead time before mass encryption.

## Data sources
- Defender XDR: `DeviceProcessEvents` (tooling), `DeviceEvents` (LSASS access), `DeviceFileEvents`
  (encryption burst); Sysmon EID 1, EID 10 (LSASS access), EID 11.

## Query logic
1. Find discovery/RMM tooling: Advanced IP Scanner, AnyDesk, SimpleHelp process creations.
2. Find credential access: LSASS-access events or `sekurlsa`/`lsadump` command lines (Mimikatz).
3. Find impact: hosts with more than ~25 `.encrypted` / note file events in a short window.
4. Correlate the three by device and time; surface hosts hitting two or more stages.

## Triage / expected vs benign
- **Malicious:** the ordered discovery to cred-dump to encryption sequence, especially post-Take
  Control (H1) or with a Cloudflared service (H2).
- **Benign:** sanctioned RMM and asset scans; encryption bursts from legitimate backup/vault tools
  (validate the note pair and the .encrypted files' parentage).

## Pivots on a hit
- Isolate before encryption spreads; identify the exfiltration channel (data theft precedes the
  locker); map reachable SMB shares from the discovery output to predict the encryption blast radius.
