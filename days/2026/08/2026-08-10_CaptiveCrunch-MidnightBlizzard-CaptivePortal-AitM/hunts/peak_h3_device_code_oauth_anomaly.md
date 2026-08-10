# PEAK Hunt H3 - Anomalous Entra device code / OAuth authentication

## Hypothesis
Storm-2945 phishes Entra ID device code authentication: it starts an auth request and tricks the
victim into entering an actor-controlled device code into the legitimate Microsoft sign-in page,
authenticating the operator's session, then registers a device and collects M365 data. If this
succeeded against us, we expect device code sign-ins from actor infrastructure or from locations
inconsistent with the user, followed by a new device registration.

## Rationale (ABLE)
- **Actor behaviour:** AI-augmented device code and OAuth code phishing since February 2026;
  device code redirects on CaptiveCrunch landings since 2026-07-16; lineage with Storm-2372.
- **Analytic value:** device code flow is rare for ordinary corporate users on managed laptops,
  so a successful deviceCode grant is inherently worth reviewing.

## Data sources
- Sentinel: `SigninLogs` (AuthenticationProtocol == "deviceCode"), `AuditLogs` (device register).
- Defender XDR: `AADSignInEventsBeta`, `CloudAppEvents`.

## Query logic
1. `SigninLogs` where `AuthenticationProtocol == "deviceCode"`.
2. Flag sign-ins whose `IPAddress` is in the CaptiveCrunch IOC set, or whose city/country is
   inconsistent with the user's 30-day baseline.
3. Correlate a successful grant (ResultType 0) with an `AuditLogs` "Add registered device" or
   "Add device" event for the same user within 24 hours.

## Triage / expected vs benign
- **Malicious:** deviceCode grant from actor IP or foreign geo, then immediate device registration
  and mailbox/SharePoint enumeration.
- **Benign:** legitimate device code use from smart TVs, IoT, or CLI tooling on known networks.

## Pivots on a hit
- Revoke sessions and refresh tokens for the user, remove the attacker-registered device, and
  review OAuth app consents and mailbox rules created after the grant.
