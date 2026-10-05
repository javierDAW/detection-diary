# PEAK hunt H1 - Reply-first impersonation of public experts from free-mail accounts

## Prepare

**Hypothesis.** If TA419 or a similar cluster targets your staff, then high-value recipients (AI policy, trade, defence, energy, legal and research staff) received a
first-contact email with no link from a free-mail address whose display name is a well-known expert, and a later message from the same sender carried a shortened URL after the
recipient replied. Proofpoint reports July 2026 senders `leparker@mail[.]com`, `hcrediker@mail[.]com` and `hcrediker@outlook[.]com`, the pretexts "AI Policy Advisory Committee" and a
Senate Committee on Foreign Relations report, and a February 2026 subject "Request for Feedback on Military Integration of Claude".

**Why first.** The first message contains no link and no attachment, so link and attachment filters have nothing to score. The only evidence is the sender, the display name and the
conversation pattern.

**Scope.** Inbound mail for the last 90 days to the people most likely to be targeted. Start with the 20 to 50 mailboxes of staff who publish on policy or are listed on public pages.

**Data quality check first.** Confirm that `EmailEvents` retention covers 90 days and that `SenderDisplayName` is populated. Without display names, rely on the three published addresses and the four lookalike sender domains.

## Execute

```kql
// Defender XDR: see kql/k1 and kql/k4 for the full queries. This one lists first-contact mail from free-mail providers that spoofs an expert display name.
let freeMail = dynamic(["mail.com","outlook.com","gmail.com","yahoo.com","proton.me","icloud.com"]);
EmailEvents
| where Timestamp > ago(90d) and EmailDirection == "Inbound"
| where SenderFromDomain in~ (freeMail)
| where SenderDisplayName has_any ("Lynne Parker","Lynne Edwards Parker","Heidi Crebo-Rediker")
| project Timestamp, RecipientEmailAddress, SenderDisplayName, SenderFromAddress, Subject
```

```kql
// Mail pattern of the reply-first gate: a link-free first contact, then a message from the same sender with a URL within 14 days.
// The reply itself is outbound mail; confirm it separately in EmailEvents with EmailDirection == "Outbound".
let withLink = EmailUrlInfo | where Timestamp > ago(90d) | summarize Urls = make_set(Url, 5) by NetworkMessageId;
let mail = EmailEvents
    | where Timestamp > ago(90d) and EmailDirection == "Inbound"
    | join kind=leftouter withLink on NetworkMessageId
    | extend HasLink = isnotempty(Urls);
mail
| where HasLink == false
| project FirstTime = Timestamp, RecipientEmailAddress, SenderFromAddress
| join kind=inner (mail | where HasLink | project LinkTime = Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Urls) on RecipientEmailAddress, SenderFromAddress
| where LinkTime between (FirstTime .. (FirstTime + 14d))
| summarize LinkMessages = count(), Subjects = make_set(Subject, 5) by RecipientEmailAddress, SenderFromAddress, FirstTime
```

## Act

**A sender or lookalike domain from the Proofpoint list** is a confirmed campaign contact. Find out whether the recipient replied, and if so whether a shortened URL followed. If it did, treat the account as exposed
and go to the H3 session checks; also check what the recipient clicked in `UrlClickEvents`.

**An expert display name from a free-mail address with no link yet** is a lead, not proof: genuine people also write from personal accounts. Verify the sender through a separate channel the recipient already trusts,
and warn the recipient that a reply may unlock a phishing link.

**No hits** do not show that you were not targeted: Proofpoint says the actor changes personas and domains, and its post lists only the ones it saw. Keep the display-name query running for the experts your staff correspond with.
