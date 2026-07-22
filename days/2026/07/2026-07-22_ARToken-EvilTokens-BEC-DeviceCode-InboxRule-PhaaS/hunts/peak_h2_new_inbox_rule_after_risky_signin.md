# PEAK Hunt H2: New Inbox Rule Created After a Risky Sign-In

## Hypothesis (PEAK format)

**If** a mailbox has been compromised for sustained business email compromise (BEC) fraud rather
than a one-time credential theft, **then** a new inbox rule with a forwarding, redirect, or
hide/delete action will be created shortly after the compromising sign-in -- the mechanism
ARToken's ARTSender module uses to suppress evidence of the fraud from the real account holder.

## Why this hunt matters

Credential theft alone is a triage-and-reset event. A new hide/forward inbox rule is the pivot
point where theft becomes an active, ongoing fraud campaign that can run for weeks against real
vendor relationships -- the single strongest available signal separating the two outcomes, and one
that is independent of which PhaaS kit or initial-access technique was used to steal the
credential in the first place.

## Data sources

- Microsoft 365 Unified Audit Log / `OfficeActivity` (`New-InboxRule`, `Set-InboxRule` operations)
- Microsoft Entra ID `SigninLogs` for the risky/anomalous sign-in used as the correlation anchor

## Procedure

1. Query the Unified Audit Log for `New-InboxRule` / `Set-InboxRule` operations where the rule
   parameters include `ForwardTo`, `RedirectTo`, `DeleteMessage`, or a `MoveToFolder` target of
   `RSS Feeds` or `Conversation History` (both common hiding locations).
2. For each hit, look back 24 hours for a risky or device-code sign-in event for the same account.
3. Prioritize accounts in finance, accounts-payable, HR, or executive-assistant roles, which are
   disproportionately targeted by BEC operators for exactly this reason.
4. For confirmed hits, immediately pull message-trace history to quantify how many outbound
   messages were sent (or replies suppressed) while the rule was active.

## Companion artifact

See `kql/artoken_new_inbox_rule_forward_or_hide.kql` for the runnable query and
`sigma/artoken_new_inbox_rule_hide_or_forward.yml` for the Sigma detection.

## Expected false positives

- Legitimate personal mailbox organization rules created by the user themselves (verify via a
  direct, out-of-band conversation with the account owner).
- IT-administered bulk mail-flow rule deployments during scheduled change windows; exclude known
  service accounts and change-ticket correlation.
