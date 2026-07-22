# PEAK Hunt H3: Mass Send-As With BCC Batching Fan-Out

## Hypothesis (PEAK format)

**If** the ARTSender module is being used to run outbound BEC fraud from a compromised mailbox,
**then** that mailbox will show an outbound send-volume spike with BCC batching and a near-uniform
inter-send delay -- an automation signature distinguishable from both normal human sending
behavior and from legitimate bulk-mail/marketing tooling by its BCC-heavy structure and its
concentration against a small number of vendor/partner recipient domains rather than a broad
subscriber list.

## Why this hunt matters

ARTSender is explicitly designed to mimic a human sending cadence via configurable inter-send
delay, which defeats naive rate-based alerting thresholds. Anchoring on the BCC-batch structure
and recipient-domain concentration, rather than raw volume alone, produces a signature that
survives an operator tuning the delay parameter.

## Data sources

- Exchange Online message trace / `Get-MessageTrace`
- Microsoft 365 Unified Audit Log `Send` operations with recipient counts

## Procedure

1. Query message trace for mailboxes sending more than 5 BCC recipients per message across
   multiple messages within a short window (start with 30-60 minutes and tune per environment).
2. Exclude known bulk-mail service accounts (`noreply@`, `marketing@`, `newsletter@` patterns and
   any environment-specific distribution service principals).
3. For survivors, compute inter-send timing variance; a low-variance, near-uniform delay between
   sends is consistent with automated batching rather than a human manually BCC-ing recipients.
4. Cross-reference recipient domains against the account's normal correspondence history --
   ARTSender's vendor-impersonation lures concentrate against a small number of real business
   relationships rather than a broad list.
5. Correlate with H2 (new inbox rule) for the same account; a mailbox showing both signatures
   together is a near-certain active BEC compromise.

## Companion artifact

See `sigma/artoken_mass_sendas_bcc_batch.yml` for the detection logic.

## Expected false positives

- Legitimate bulk-mail, ticketing, or notification service accounts not yet covered by the
  exclusion list -- extend the filter per environment.
- Helpdesk/IT accounts performing legitimate mass notifications during incidents or outages.
