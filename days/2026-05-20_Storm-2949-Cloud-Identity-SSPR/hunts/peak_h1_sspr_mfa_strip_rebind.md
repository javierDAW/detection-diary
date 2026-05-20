# PEAK H1 — SSPR + MFA Method Strip + Authenticator Rebind on Same Principal

## Hypothesis

A threat actor has used Self-Service Password Reset (SSPR) plus vishing to
take over a user account by completing the SSPR flow, removing every prior
MFA method (phone, email, prior Microsoft Authenticator registration), and
registering a new Microsoft Authenticator device under operator control —
all within a five-minute window on the same principal.

## Why this discriminates

Legitimate MFA re-registration after a lost or replaced device normally
takes longer, pairs with a help-desk ticket, and typically does not chain
with a successful SSPR event on the same principal. The combination
**SSPR success + multiple authentication-method removals + new Authenticator
registration** within five minutes is a near-zero-FP anchor for
Storm-2949-class SSPR abuse and equivalent identity takeovers that traverse
SSPR.

## Data sources

- Microsoft Entra ID `AuditLogs` (Categories `UserManagement`,
  `AuthenticationMethods`).
- Microsoft Defender for Identity `IdentityDirectoryEvents`.
- Microsoft Sentinel or Defender XDR advanced hunting.

## Query (KQL)

See `../kql/storm2949_sspr_mfa_strip_rebind_chain.kql`.

## Expected benign vs malicious

- **Benign:** end-user MFA re-registration after a help-desk-acknowledged
  lost or replaced device; service-account-initiated bulk MFA migration
  during a documented change window.
- **Malicious:** target principal is privileged (IT, leadership, admin
  role membership); InitiatedBy is the target user (self-service flow);
  no help-desk ticket in the ITSM system within +/- 1 hour; sign-in from
  a new IP / new user agent immediately after the rebind.

## Action on match

1. Disable the affected principal at Entra ID and revoke all refresh tokens
   (`Revoke-MgUserSignInSession`).
2. Out-of-band contact (in-person or known good phone) with the legitimate
   user to confirm whether the SSPR was initiated by them.
3. Snapshot Entra `signInLogs` and Azure `AzureActivity` for the principal
   for the last 30 days; tag and freeze.
4. If confirmed malicious, walk the `peak_h2_arm_credential_burst.md` and
   `peak_h3_vmaccess_runcommand_imds.md` hunts to scope blast radius into
   Azure.

## References

- Microsoft Security Blog — Storm-2949 (2026-05-18).
- PEAK Threat Hunting Framework — Splunk / SURGe (note: process applies
  regardless of SIEM brand).
