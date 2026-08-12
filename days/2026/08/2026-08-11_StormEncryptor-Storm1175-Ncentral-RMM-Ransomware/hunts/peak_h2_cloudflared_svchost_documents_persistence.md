# PEAK Hunt H2 - Cloudflared tunnel + svchost-in-Documents persistence

## Hypothesis
Storm-1175 establishes persistent remote access by installing Cloudflare Tunnel (cloudflared) as a
Windows service and planting a svchost.exe inside a user's Documents folder. If a host is implanted
we expect a Cloudflared service and/or a svchost.exe process whose image path is under
`\Documents\` - neither of which is normal for the legitimate service host.

## Rationale (ABLE)
- **Actor behaviour:** legitimate-tool persistence (cloudflared is signed and benign in isolation)
  plus name masquerade against svchost.exe run from a user-writable path.
- **Analytic value:** the Documents svchost.exe path is a near-zero-false-positive artifact; the
  Cloudflared service on a non-developer asset is a strong, specific signal.

## Data sources
- Defender XDR: `DeviceProcessEvents`, `DeviceFileEvents`; Sysmon EID 1 (process create),
  EID 11 (file create), EID 13 (registry set for the service).

## Query logic
1. `DeviceProcessEvents` where `FileName` is svchost.exe and `FolderPath` contains `\Documents\`.
2. `DeviceProcessEvents` where `FileName` is cloudflared.exe with `tunnel run` / `--token` /
   `trycloudflare` in the command line, or a service named Cloudflared in `DeviceRegistryEvents`.
3. Union per device; prioritise hosts showing both.

## Triage / expected vs benign
- **Malicious:** any svchost image outside System32/SysWOW64; Cloudflared service on servers or
  endpoints with no sanctioned tunnel use.
- **Benign:** developers/IT who legitimately run Cloudflare Tunnel; confirm by asset owner.

## Pivots on a hit
- Recover the cloudflared config/token to identify the tunnel account; check egress to
  `*.argotunnel.com` / `trycloudflare.com`; correlate with Take Control sessions (H1).
