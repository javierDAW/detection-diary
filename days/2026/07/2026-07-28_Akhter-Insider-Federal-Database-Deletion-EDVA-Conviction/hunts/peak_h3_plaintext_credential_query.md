# PEAK Hunt H3 -- Plaintext credential retrieval from an application store

**Author:** Jarmi
**Date:** 2026-07-28
**ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files), T1213 (Data from Information Repositories)

## Hypothesis
A privileged operator queries an application's backing store and retrieves a user password in a
form that is usable to authenticate elsewhere, because the application persists passwords in
plaintext or reversibly. In the Akhter case a routine query against the EEOC Public Portal store
returned a complainant's plaintext password, which was reused to seize their email.

## Prepare
- Telemetry: database audit logs (SELECT statements + object names), application access logs,
  DLP on password-shaped strings leaving the DB tier.

## Execute
1. Enumerate columns/tables that hold credential material (`password`, `secret`, `token`).
2. Alert on interactive/ad-hoc SELECT of those columns outside the application service account.
3. Cross-reference the returned account against subsequent logons from new locations/devices.

## Analyze / Act
- Any human-run SELECT of credential columns is suspicious; verify need-to-know.
- Remediate the root cause: hash with a slow KDF (argon2id/bcrypt/scrypt), remove reversible
  storage, and segregate secrets so a routine query cannot return them.
