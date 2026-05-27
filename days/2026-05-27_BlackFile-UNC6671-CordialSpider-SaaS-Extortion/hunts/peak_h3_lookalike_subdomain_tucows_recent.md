# PEAK Hunt H3 — Recent Tucows-registered lookalike subdomain with passkey / enrollment / SSO tokens

## Hypothesis

If UNC6671 / BlackFile / Cordial Spider staging activity has been directed at
the organisation, then DNS resolver logs, egress proxy logs or CASB telemetry
will show one or more internal hosts resolving a subdomain on a recently
registered (less than 14 days old) Tucows-managed apex domain whose subdomain
label contains the organisation's own name as a literal segment, plus one of
the apex names `enrollms[.]com`, `passkeyms[.]com`, or `setupsso[.]com`. The
resolution will typically happen minutes after a vishing call to the same
user.

## Why this discriminates

UNC6671's staging pattern is highly deterministic, per GTIG 2026-05-15: a
Tucows-registered domain stood up minutes before the call (so DNS reputation
is at its blindest), with a per-victim subdomain containing the
organisation's name literally embedded. Three apex names recurred across
multiple GTIG-documented campaigns. The subdomain freshness (less than 14
days; commonly less than 24 hours) is rare for any legitimate enterprise
SaaS vendor — vendors keep apex names stable across multi-year tenancies.
The combination of (a) Tucows registrar, (b) less than 14 days old, (c)
apex in the lookalike set, (d) subdomain label literal-contains the
organisation's name, is therefore a high-confidence signal.

## Expected benign

- A genuine vendor stood up a per-tenant subdomain on one of these apex
  names. (Extremely rare; verify with sourcing / procurement.)
- A red-team or purple-team engagement emulating UNC6671 tradecraft. Verify
  against the engagement schedule.
- A security-awareness platform running a controlled phishing simulation
  with similar tradecraft. Verify with the awareness team.

## Expected malicious

- The subdomain was first seen in the organisation's DNS resolver in the
  last hour.
- The first source host to resolve the subdomain is the executive assistant
  / IT-operations / privileged user identified in a contemporaneous Sigma
  hit (rule 01 or 02 in this folder).
- The HTTPS handshake to the subdomain takes the user to an SSO portal
  visually identical to the corporate login.
- The subdomain naming convention is per-victim (literal organisation name
  in the label).

## Actions

1. Pull the last 14 days of DNS resolver logs filtered on the three apex
   domains.
2. Join against passive DNS sources (Farsight DNSDB, VirusTotal, etc.) and
   the GTIG VirusTotal Collection
   (`59b667464a0d3c503320bfa43b165d4633288fd0d4226ff51108ac0f9dd02a97`).
3. For every subdomain returned, check WHOIS registrar; if Tucows and
   created less than 14 days ago, escalate.
4. Block the resolved subdomain at the DNS resolver, the egress proxy, and
   the email security gateway. Add the apex to the proxy denylist if not
   already there.
5. For every internal host that resolved the subdomain in the last 30 days,
   run hunts H1 and H2 against the associated user account.
6. Submit the lookalike subdomain to Google Safe Browsing and Microsoft
   SmartScreen for ecosystem-wide blocking.
