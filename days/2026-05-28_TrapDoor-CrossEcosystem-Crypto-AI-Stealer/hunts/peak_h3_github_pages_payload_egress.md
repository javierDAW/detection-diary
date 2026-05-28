# PEAK H3 — Egress to `ddjidd564.github.io` or campaign URI in the last 14 days

## Hypothesis
Any developer workstation, build agent or CI/CD runner that has resolved DNS
for `ddjidd564.github.io` or that fetched a URI matching
`/defi-security-best-practices/*` from GitHub Pages in the last 14 days has
hit the TrapDoor configuration / payload host and should be treated as
compromised until proven otherwise.

## Why this discriminates
GitHub Pages is general-purpose hosting. The campaign uses a single attacker
account — `ddjidd564` — and a single campaign repo —
`defi-security-best-practices`. The DNS / TLS / HTTP anchor is exact. There
is no documented legitimate use of this host today; until the account is
decommissioned by GitHub, a hit is a near-deterministic campaign indicator.
The same host also serves the JSON config referenced by the
`browser-use/browser-use` poisoned PR.

## Expected benign vs malicious
- Benign: a security researcher actively investigating TrapDoor from a
  sanctioned analysis host (allowlist by DeviceName or by ANALYST account).
- Malicious: any other host on the corporate network that touches the FQDN,
  the campaign URI, or the `config.json` endpoint.

## Actions on match
1. Pull the full 14-day timeline of DNS, TLS SNI and HTTP egress to the host
   from DeviceNetworkEvents, perimeter NetFlow, and the proxy log.
2. Identify the parent process (`node`, `npm`, `python`, `python3`, `cargo`,
   `rustc`, `curl`, `wget`, `powershell`, `pwsh`) and the originating package
   name or repository.
3. Capture trap-core.js if present on disk; compare its `48485`-byte size and
   content with the Socket reference and the YARA anchor.
4. Run the H1 and H2 hunts retroactively against every host that hit this
   anchor.
5. Block the FQDN at the proxy / DNS sinkhole; report the GitHub Pages account
   `ddjidd564` to GitHub Trust & Safety; report the affected packages to npm
   / PyPI / Crates.io.
