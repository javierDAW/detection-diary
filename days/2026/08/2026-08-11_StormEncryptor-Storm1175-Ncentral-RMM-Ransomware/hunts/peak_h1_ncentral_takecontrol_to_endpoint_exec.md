# PEAK Hunt H1 - N-central Take Control to managed-endpoint execution

## Hypothesis
After exploiting the N-able N-central auth bypass (CVE-2026-18577), Storm-1175 abused the built-in
Take Control feature to reach managed endpoints and run tooling. If a self-hosted N-central server
was exposed, we expect Take Control sessions (or agent-initiated remote command execution) closely
followed on the managed endpoint by new binaries in unusual paths (svchost.exe in Documents,
cloudflared) or remote-access tools (AnyDesk, SimpleHelp).

## Rationale (ABLE)
- **Actor behaviour:** RMM-as-initial-access - compromise the management server, then use its
  legitimate agent channel to push execution downstream, minimising exploit noise on the endpoint.
- **Analytic value:** the pivot bridges a server-side auth bypass and endpoint execution; the join
  key is the N-central agent process spawning children shortly after an anomalous admin session.

## Data sources
- N-central: authentication logs, Take Control session activity, administrative account changes.
- Endpoint (Defender XDR / Sysmon): `DeviceProcessEvents` where the N-central agent
  (e.g. `BASupSrvc*`, `Take Control` helper) is the initiating process; EID 1.

## Query logic
1. From N-central, list Take Control sessions and admin logins in the exposure window (from
   2026-08-01) that do not map to a known technician.
2. On the managed endpoints in scope, find children of the N-central agent that write or launch
   executables outside standard install paths within minutes of that session.
3. Rank hosts by (unknown Take Control session) AND (anomalous child execution).

## Triage / expected vs benign
- **Malicious:** agent-spawned cloudflared, svchost.exe in Documents, AnyDesk/SimpleHelp install,
  Advanced IP Scanner, or Mimikatz shortly after an unattributed Take Control session.
- **Benign:** scheduled patching/scripting pushed by real technicians; validate against the ticket
  system and the technician roster.

## Pivots on a hit
- Pull the endpoint's Cloudflared service and the Documents svchost.exe for scoping; check LSASS
  access events for Mimikatz; enumerate lateral connections to the N-able-published IPs.
