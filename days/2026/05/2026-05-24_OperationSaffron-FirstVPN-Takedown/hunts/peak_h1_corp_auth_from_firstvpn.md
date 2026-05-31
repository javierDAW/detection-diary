# PEAK H1 — Retro hunt: corporate authentication from First VPN exit node in the last 24 months

## Hypothesis
In the 24 months prior to the Operation Saffron takedown (19-20 May 2026), at least one ransomware affiliate, IAB, or other cybercrime operator authenticated successfully to our identity provider, corporate VPN, RDP gateway, or public SSH bastion from a First VPN Service exit IP using a valid corporate account. The historical record now exists because the FBI FLASH-20260521-001 publishes a 98-IP list with a clear current-vs-historical split.

## Why this discriminates
Before this dataset existed, the affiliate's true country was hidden behind the exit-node country at the identity-provider layer; impossible-travel and risky-IP scoring missed the auth. With the published list, **any** successful auth from a current or historical First VPN IP is high-fidelity. The detection cost in 2024-2026 was effectively zero because the IP list was not public; the cost is now equally low because the list is public and the dataset is bounded.

## Expected benign vs malicious
- Benign: a traveling user behind a commercial VPN that, after the FBI rotation cutoff, was reassigned a previously historical First VPN IP. Distinguish by checking whether the IP is in the **current** FBI list (high suspicion) vs the **historical** FBI list (need to validate against the IP's current ASN ownership). Also benign: SOC analyst manually validating an IOC by performing a deliberate test auth — whitelist analyst hosts.
- Malicious: any successful auth from the current-IP list against a user who is not currently a traveler or who has no documented commercial-VPN usage. Especially malicious if the same account also authenticated normally from an unrelated geo within the same 24-hour window.

## Data sources
- Microsoft Entra ID — `SigninLogs` (Sentinel) or Graph API `Get-MgAuditLogSignIn`.
- Okta System Log — `eventType eq "user.authentication.sso"` filtered by `client.ipAddress`.
- Duo Auth API — `event_type=authentication`.
- Corporate VPN gateway syslog — Fortinet, Palo Alto GlobalProtect, Cisco AnyConnect / ASA, Pulse / Ivanti, Citrix NetScaler.
- RDP gateway and public-facing SSH bastion logs.

## Search logic (Sentinel KQL example)
See [`../kql/firstvpn_signin_from_known_node.kql`](../kql/firstvpn_signin_from_known_node.kql). The same logic applies to Okta, Duo, and VPN-gateway log tables — substitute the IP-column name (`client.ipAddress`, `src_ip`, `access_device.ip`, etc.).

## Time window
Two years (730 days) retroactive from today.

## Action on match
1. Open a triage ticket per `(UserPrincipalName, IPAddress)` pair.
2. For every match, pull the user's session history in the 30 days following the First VPN auth; look for privilege escalation, token rotation, mailbox rule changes, or new OAuth grants — see Day 23 Storm-2949 playbook for the cloud control-plane pivot pattern.
3. If the user is privileged or a tier-0 administrator, treat as full identity compromise — force password reset, revoke refresh tokens, rotate any service-principal secrets owned by the user, audit recent role assignments.
4. Correlate the IP/timestamp against the open ransomware IR tickets of the same period — a retroactive First VPN match in the affiliate's recon window is a high-value dwell-time anchor for after-action review.

## Notes
- The historical-IP list (pre-May 2026 rotation) has ~65 entries; some are now reassigned to legitimate hosting customers. Run the historical list against the current ASN ownership before mass-blocking — preserve forensic value but do not collateralize legitimate services.
- Pair this hunt with PEAK H3 (failed-then-success burst from the same IP) for higher-confidence ranking. Both should be considered when reviewing the affiliate's pre-encryption recon and dwell-time pattern.
