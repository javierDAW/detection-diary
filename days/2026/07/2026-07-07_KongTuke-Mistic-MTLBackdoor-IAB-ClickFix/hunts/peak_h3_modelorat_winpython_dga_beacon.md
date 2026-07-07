# PEAK Hunt H3 — ModeloRAT WinPython Persistence and DGA Beacon

**Hypothesis:** Woodgnat established durable access via ModeloRAT — a portable WinPython
distribution (`WPy64-31401`) run through signed `pythonw.exe`, persisted under an HKCU Run key
whose name impersonates AnyDesk/Splashtop/Comms, beaconing over RC4-encrypted C2 with a
weekly-rotating DGA on non-domain-joined hosts.

**Prediction / expected evidence:** A Run-key value pointing at a portable `pythonw.exe` in a
user-writable path; `pythonw.exe` making outbound connections to newly-registered `.top`/`.com`
domains with high-entropy labels; `net.exe`/`nltest`/Kerberoast recon shortly after.

## Data sources
- Defender XDR `DeviceRegistryEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`.
- Sysmon EID 13 (Run key), EID 1 (pythonw.exe lineage), EID 22 (DNS).

## Analytic (Defender XDR)
See `kql/modelorat_winpython_persistence.kql` for persistence, then join `pythonw.exe`
`DeviceNetworkEvents` and score `RemoteUrl` label entropy to surface DGA candidates
(`b6w9m2z5x8q1v3k[.]top`, `w3xasv14culvnqj[.]top`, `cj06y9v4xab[.]com` are seed examples).

## Triage
- Distinguish corporate (domain-joined) vs WORKGROUP hosts — ModeloRAT reserves the heavier
  DGA variant for standalone hosts and the richer payload for enterprise targets.
- Revoke persistence, then hunt for the IAB handoff (new admin accounts, RMM installs) that
  typically precedes a ransomware affiliate (Qilin/Akira/Rhysida) taking over.

## Outcome
- [ ] Confirmed ModeloRAT  - [ ] Benign Python tooling  - [ ] Inconclusive
