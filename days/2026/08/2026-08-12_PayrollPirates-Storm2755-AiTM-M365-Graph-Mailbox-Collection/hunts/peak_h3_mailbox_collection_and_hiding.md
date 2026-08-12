# PEAK Hunt H3 - Coordinated mailbox collection and selective inbox-hiding rules

## Hypothesis
The operator retrieves finance-related messages using the anomalous Outlook ClientAppId +
undocumented API ID pairing (Bind access), with cross-tenant `MailItemsAccessed` events
clustering into very short windows (centralized automation). In a small subset of intrusions,
operators create inbox rules that move messages to Deleted Items and mark them read.

## Data sources
- Defender XDR `CloudAppEvents` / Exchange Online unified audit log (`MailItemsAccessed`, `New-InboxRule`)

## Analytic steps
1. Find `MailItemsAccessed` where `ClientAppId == 5d661950-3475-41cd-a2c3-d671a3162bc1`
   AND `AppId == c999ed3e-27ae-4cb3-b3a2-46b056af63d3`; confirm `AccessType == Bind`.
2. Bucket events by 60-second windows across tenants/accounts; flag bursts (e.g. 10+ events in <60s).
3. Search `New-InboxRule`/`Set-InboxRule` where the action moves mail to Deleted Items and marks read.
4. Tie inbox-rule sign-ins (often interactive, from hosting ASNs such as AS27176 Datawagon) back to
   the shared `SessionId` from H1.

## Expected benign
The ClientAppId+AppId pairing has no known legitimate use, so a match is high-fidelity. Move-to-
Deleted inbox rules exist legitimately, so scope those to accounts already implicated by H1/H2.

## Related detections
- kql/m365_mailitemsaccessed_anomalous_pairing.kql
- sigma/m365_mailitemsaccessed_anomalous_appid_pairing.yml
