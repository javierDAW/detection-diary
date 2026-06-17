# PEAK Hunt H3 — Post-harvest account takeover and Telegram relay

**Hypothesis.** If credentials and OTP were harvested, then a recently-lured account shows **sign-in
anomalies** (new ASN/geo), **new inbox/forwarding rules** or **unexpected OAuth grants**, and the
device that submitted the credentials contacted the kit's **Telegram-relay** endpoint
(`/check_telegram_updates.php`).

**Why these signals.** The kit captures the second factor in real time, so a stolen credential is
immediately usable. Account takeover then manifests as anomalous sign-ins plus persistence
(forwarding rules, OAuth apps). The Telegram relay is the operator's exfil channel.

## Prepare
- Identify the candidate user set from H1 (anyone who POSTed to a kit endpoint).
- Ensure `SigninLogs` / `IdentityLogonEvents`, M365 unified audit log and `CloudAppEvents` are on.

## Execute
- For each lured user, pull sign-ins for 14 days after the click and flag new country/ASN, new
  device, or impossible travel.
  ```kql
  SigninLogs
  | where TimeGenerated > ago(14d)
  | where UserPrincipalName in (loweredCandidateUPNs)
  | summarize Countries=make_set(Location), ASNs=make_set(AutonomousSystemNumber), IPs=make_set(IPAddress) by UserPrincipalName
  ```
- Enumerate inbox/forwarding rules and recent OAuth grants per affected mailbox:
  ```powershell
  Get-InboxRule -Mailbox user@corp.example | Select Name,Enabled,ForwardTo,RedirectTo,DeleteMessage
  ```
- Confirm the device-side Telegram relay with the H1 URI query (`/check_telegram_updates.php`).

## Analyze / pivot
- A new forwarding rule or OAuth grant created **after** the click is takeover persistence — remove
  it and treat the mailbox as compromised.
- Anomalous sign-in + a valid recent OTP capture = live session hijack: **revoke sessions/tokens**,
  not just reset the password.
- Look for outbound BEC behaviour from the mailbox: payment-change requests, vendor thread hijacks,
  bulk internal phishing.

## Document / hand off
- Record per-account: anomalous sign-ins, rogue rules/grants, and exfil confirmation.
- Drive remediation: reset + re-MFA, revoke sessions, remove persistence, and move the user to a
  phishing-resistant factor (FIDO2 / passkey).
- Capture lessons: which control would have stopped it earliest (passkeys, RMM allowlist, proxy
  block of the kit URI chain).
