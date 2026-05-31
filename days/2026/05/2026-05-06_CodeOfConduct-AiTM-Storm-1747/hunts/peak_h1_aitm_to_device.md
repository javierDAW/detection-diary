# PEAK H1 — Click → Device-Add (Tycoon2FA AiTM)

**Author:** Jarmi
**Date:** 2026-05-06
**Reference:** [Microsoft — Breaking the code (4-may-2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)

## Hypothesis

> Any user who clicks a URL on a cheap TLD (`.de`, `.space`, `.email`, `.solutions`, `.live`, `.today`, `.calendar`, `.click`) and registers a device in Entra ID within the next 2 hours is compromised via AiTM (Tycoon2FA-class).

## Why this works (rationale)

- Tycoon2FA migrated away from Cloudflare to cheap TLDs (Mar 2026), with FQDNs lasting 24-72h.
- After the AiTM step, the operator seeks immediate persistence; Microsoft observed `device join` in <10 min on a portion of the victims.
- Legitimate BYOD enrollments *also* register devices, but the temporal overlap with a click on a cheap TLD is very rare in baseline traffic.

## Data sources

- `UrlClickEvents` (Defender XDR — Safe Links clicks).
- `AuditLogs` (Entra ID Diagnostics → Sentinel) — `Add device` operation.

## Query (Defender XDR / Sentinel)

See [`../kql/peak_h1_click_to_device.kql`](../kql/peak_h1_click_to_device.kql).

## Expected vs benign

- **Benign baseline (medium tenant):** 0-3 hits/week (personal BYOD with personal-domain redirect).
- **Anomalous:** ≥1 hit with click → device-add < 30 min, OR ≥3 hits on the same TLD within 72h, OR any hit where the sign-in immediately preceding the device-add has `RiskLevelDuringSignIn ≥ medium`.

## Triage steps on hit

1. Inspect the clicked `Url` and dump the PDF that linked to it if present in `EmailUrlInfo`.
2. Validate whether the added device is legitimate: `Get-MgDevice -DeviceId <id>` and check `OperatingSystem`, `EnrollmentType`, `RegistrationDateTime`.
3. Cross-check with `IdentityLogonEvents` for SSO activity from the suspicious device.
4. If confirmed malicious: `Remove-MgDevice` + `Revoke-MgUserSignInSession` + password reset + FIDO2 enrolment.
5. Pivot laterally with query 3 (`aitm_chain_correlation.kql`) to surface inbox rules created by the same user within the next 24h.

## Out-of-scope / known limitations

- Tycoon2FA is starting to use TLDs not on the list (`.support`, `.online`); review the list quarterly.
- If the tenant runs Defender for Endpoint without Safe Links, `UrlClickEvents` may be empty; use SWG / web-proxy logs as a substitute.
- This hypothesis does NOT cover the case where the operator does NOT register a device and only reuses session cookies; for that, see `aitm_chain_correlation.kql` anchored on risky sign-in + inbox rule.
