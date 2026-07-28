# PEAK Hunt H1 -- Post-termination authentication and privileged action

**Author:** Jarmi
**Date:** 2026-07-28
**ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts)

## Hypothesis
An account belonging to a recently offboarded employee or contractor authenticates and performs
privileged actions after the person's termination timestamp, because deprovisioning lagged the
HR event. In the Akhter EDVA case the abuse began minutes after the termination meeting while
credentials were still live.

## Prepare
- Authoritative leaver feed: HR termination time per identity (or AD `whenChanged` on disable).
- Telemetry: `IdentityLogonEvents`, `DeviceLogonEvents`, VPN/RDP gateway logs, DB auth logs.

## Execute
1. Build a leaver table (UPN -> termination_time).
2. Join authentication events where `Timestamp > termination_time` (allow a small documented grace window).
3. Rank by privilege of the action that followed (DB admin, backup, file share, mail).

## Analyze / Act
- Any successful post-termination logon that is not an approved handover is an incident.
- Escalate immediately if followed by destructive verbs (see H2) or log clearing.
- Feed confirmed gaps back into deprovisioning SLA metrics (time-to-disable).
