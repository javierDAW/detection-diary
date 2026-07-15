# PEAK Hunt H1 — Attacker-registered passkey after anomalous sign-in

**Hypothesis.** An O-UNC-066 (Pink) operator, having relayed a victim's credentials and MFA through the vishing kit, has enrolled their own passkey (FIDO2) into a Microsoft 365 account in our tenant. If true, there is an authentication-method registration event that closely follows a sign-in from an unfamiliar ASN/geo (in some cases DDoS-Guard AS57724 or IQWeb AS59692), for a user who did not knowingly enrol a passkey.

**Why this is the durable signal.** The campaign has no malware hash and its domains rotate. The one artefact that must exist for the attack to succeed is a *new authenticator on the account* — a `fido2AuthenticationMethod` added to the user object and an Entra audit `User registered security info` / `Add passkey` event. That persists in the directory even after the phishing infrastructure is gone.

**Data.** Entra `AuditLogs` (Category `UserManagement`, OperationName `User registered security info` / `Add passkey (device-bound)`) joined to `SigninLogs` (ResultType 0) by UPN within a 30-minute window. See `../kql/signin_then_passkey_registration_correlation.kql`.

**Run.**
1. List all passkey/security-info registrations in the last 30 days.
2. For each, find the nearest preceding successful interactive sign-in for that UPN; capture IP, ASN, location, device.
3. Flag registrations where the preceding sign-in is from a new-for-user ASN, an impossible-travel hop, or AS57724/AS59692.
4. Confirm with the user whether they knowingly enrolled a passkey; ask helpdesk whether they initiated it.

**Triage / expected vs benign.** Benign: user- or helpdesk-driven enrolment during a known rollout, from a normal location. Suspicious: registration the user does not recognise, or one preceded by an actor-ASN sign-in. Escalate to the IR playbook: revoke sessions, delete the rogue authenticator, force re-enrolment.

**Pivots.** Rogue passkey `displayName` (operator may reuse a word from the fake seed phrase); the registering IP; other accounts registered from the same IP/ASN in the same window.
