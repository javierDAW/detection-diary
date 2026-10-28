# PEAK hunt H2 - rogue Entra devices, MFA method swaps and new enterprise applications

## Prepare

**Hypothesis.** After a replayed session the actor persists through Device Registration Service: at least 48 devices named DESKTOP- plus eight hex characters, wiped and replaced MFA methods (19 organizations within three hours of first sign-in) and an authenticator labelled like a phone. Huntress also advises hunting for new enterprise applications and user consent.

**Why second.** Persistence outlives a password reset, so this decides whether containment is complete.

**Scope.** Entra audit logs 60 days, device inventory, authentication methods per affected user, enterprise applications and consent grants since 2026-07-14.

## Execute

```kql
// Author: Jarmi
// Sentinel: rogue device names and MFA wipe-then-register pairs (full query in kql/k2).
AuditLogs
| where TimeGenerated > ago(60d)
| where OperationName in ("Add device","User deleted security info","User registered security info")
| mv-expand tr = TargetResources
| where tostring(tr.displayName) matches regex @"^DESKTOP-[0-9A-F]{8}$" or OperationName has "security info"
| project TimeGenerated, OperationName, Actor=tostring(InitiatedBy.user.userPrincipalName), Ip=tostring(InitiatedBy.user.ipAddress), Target=tostring(tr.displayName)
```

## Act on

- Matching device registered from a hosting address, or MFA wiped and re-registered within three hours of a risky sign-in: remove the device and method, then re-check the user's mail rules (H3).
- Device name matches but the owner confirms it and the IP is theirs: record as benign and note the naming scheme. The pattern is not unique to this actor.
- New enterprise application or consent grant after 2026-07-14: disable user consent and require admin review.

## Knowledge

Names and labels are weak indicators; the pairing of events and the source IP carry the evidence.
