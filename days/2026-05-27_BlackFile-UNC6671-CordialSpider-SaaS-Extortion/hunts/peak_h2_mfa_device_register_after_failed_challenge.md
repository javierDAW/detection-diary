# PEAK Hunt H2 — MFA device registration within 5 minutes of a failed or abandoned MFA challenge

## Hypothesis

If an adversary-in-the-middle (AiTM) identity compromise of the UNC6671 /
BlackFile / Cordial Spider class is present in the environment, then an
Entra ID `AuditLogs` event of type `User registered security info` or
`Add registered security info` will appear within five minutes after a
`SigninLogs` failure for the same `UserPrincipalName` whose failure reason
indicates an MFA challenge was issued and not successfully completed (failed,
abandoned, declined, or timed out). The source IP of the audit event will
frequently differ from the source IP of the sign-in failure — operator
infrastructure vs victim infrastructure.

## Why this discriminates

In the UNC6671 workflow, the live AiTM session captures the credentials and
walks the user through the MFA challenge in real time. There are two
plausible histories of how the audit log will record this:

1. The operator enrolls the new MFA device immediately after the first
   successful sign-in. In this case the audit event has the operator's IP
   and is preceded by a successful sign-in. (Caught by other rules.)
2. The victim mis-types or hesitates during the live session, generating one
   or more failed/abandoned MFA challenges from the lookalike portal; the
   operator then steers the victim back to "complete enrollment", at which
   point the audit event fires from either the victim's IP (operator using
   the captured session against the IdP from the victim's geographic origin
   via a residential proxy) or the operator's IP. The latency between the
   final failure and the registration is short — typically under five
   minutes.

The five-minute window plus the `MFA failure → device registration` ordering
is the discriminator. Legitimate MFA-method updates by a user who just had a
failure are normally separated by minutes-to-hours of help-desk
interaction; the AiTM cadence is sub-minute to a-few-minutes.

## Expected benign

- A user genuinely losing access to their device, contacting help-desk, and
  re-enrolling within the five-minute window. Verify with the help-desk
  ticket system.
- Bulk MFA re-enrollment as part of a tenant-wide MFA-platform migration.
  Allowlist by date range.
- Conditional-access policy change that triggers a "re-register" prompt.
  Allowlist by `OperationName` or `InitiatedBy`.

## Expected malicious

- The audit event source IP is on a commercial VPN or residential proxy ASN.
- The audit event source IP differs from the sign-in failure source IP and
  one of them is anonymizer infrastructure.
- The user has no help-desk ticket in the matching window.
- The user is privileged (IT operations, finance, legal, executive
  assistant, M&A).
- A second SharePoint or OneDrive access burst from a non-managed device
  follows within hours.

## Actions

1. Run `kql/k3_entraid_mfa_register_after_failed_challenge.kql` for the last
   14 days.
2. For each hit, cross-check the help-desk ticket system for a matching
   user request in the same time window.
3. For each unmatched hit, pivot on the user and run the H1 hunt to find
   subsequent scripting-library SharePoint access.
4. If confirmed, revoke sessions and remove the newly registered MFA method
   immediately; the user has been AiTM-compromised.
5. Extend the hunt to 24 months of audit-log retention, batched by month, to
   catch the operator's earlier intrusions before the rebrand.
