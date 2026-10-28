# PEAK hunt H3 - hiding inbox rules and the payroll or BEC follow-on

## Prepare

**Hypothesis.** Compromised mailboxes carry hiding rules: names of one to three characters or punctuation ('.', 'sss', 'iT', ',.'), moves to RSS Feeds, RSS Subscriptions or Conversation History, mark-as-read, and rules for payroll, direct deposit, bank or bonus mail; four were created through the Outlook REST API. The follow-on included spam from the mailbox and a payroll-themed email to an outside CPA.

**Why third.** It finds the business impact and the people to warn (payroll, finance, external accountants).

**Scope.** Exchange admin audit and CloudAppEvents 60 days for affected users, then sent items from 2026-07-14.

## Execute

```kql
// Author: Jarmi
// Defender XDR: suspicious inbox rules (full query in kql/k3).
CloudAppEvents
| where Timestamp > ago(60d) and ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend Params = tostring(RawEventData.Parameters), RuleName = tostring(RawEventData.Item.Name)
| where strlen(RuleName) between (1 .. 3) or Params has_any ("RSS Feeds","RSS Subscriptions","Conversation History","payroll","direct deposit")
| project Timestamp, AccountDisplayName, IPAddress, UserAgent, RuleName, Params
```

## Act on

- Hiding rule plus an outbound message to payroll, a bank or an external CPA: call the recipient, freeze changes to payment details and treat as active BEC.
- Hiding rule from a hosting or VPN address that is not the user's: delete the rule, review sent and deleted items, and check forwarding.
- Short-named rule created by the user from the Outlook client: low priority; confirm with the user.

## Knowledge

BEC begins as an identity compromise: the mail rule is the hand-off. Detect the rule and the preceding sign-in as one story.
