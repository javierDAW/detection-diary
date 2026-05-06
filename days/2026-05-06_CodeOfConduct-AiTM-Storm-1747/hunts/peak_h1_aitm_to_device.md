# PEAK H1 — Click → Device-Add (Tycoon2FA AiTM)

**Author:** Jarmi
**Date:** 2026-05-06
**Reference:** [Microsoft — Breaking the code (4-may-2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)

## Hypothesis

> Cualquier usuario que haga click sobre URL en TLD barato (`.de`, `.space`, `.email`, `.solutions`, `.live`, `.today`, `.calendar`, `.click`) y registre un device en Entra ID en las 2h siguientes está comprometido vía AiTM (Tycoon2FA-class).

## Why this works (rationale)

- Tycoon2FA migró de Cloudflare a TLDs baratos (Mar 2026) con FQDNs de 24-72h.
- Post-AiTM, el operador busca persistencia inmediata; Microsoft observó `device join` en <10 min en parte de las víctimas.
- BYOD legítimo *también* registra devices, pero el solapamiento temporal con click a TLD barato es muy raro en baseline.

## Data sources

- `UrlClickEvents` (Defender XDR — clicks de Safe Links).
- `AuditLogs` (Entra ID Diagnostics → Sentinel) — operación `Add device`.

## Query (Defender XDR / Sentinel)

Ver [`../kql/peak_h1_click_to_device.kql`](../kql/peak_h1_click_to_device.kql).

## Expected vs benign

- **Benigno baseline tenant medio:** 0-3 hits/semana (BYOD personal con dominio personal).
- **Anómalo:** ≥1 hit con click → device-add < 30 min, o ≥3 hits del mismo TLD en 72h, o cualquier hit donde el sign-in que precede al device-add tenga `RiskLevelDuringSignIn ≥ medium`.

## Triage steps si hay hit

1. Ver el `Url` clickado y dump del PDF que enlazaba si está en `EmailUrlInfo`.
2. Validar si el device añadido es legítimo: `Get-MgDevice -DeviceId <id>` con `OperatingSystem`, `EnrollmentType`, `RegistrationDateTime`.
3. Cruzar con `IdentityLogonEvents` para ver actividad SSO desde el device sospechoso.
4. Si confirmado malicioso: `Remove-MgDevice` + `Revoke-MgUserSignInSession` + reset password + enrol FIDO2.
5. Buscar lateralmente con la query 3 (`aitm_chain_correlation.kql`) para encontrar inbox rules creadas por el mismo user en las 24h siguientes.

## Out-of-scope / known limitations

- Tycoon2FA ya empieza a usar TLDs no listados (`.support`, `.online`); revisar trimestralmente la lista en la query.
- Si el tenant tiene Defender for Endpoint sin Safe Links, `UrlClickEvents` puede estar vacío; usar logs del web proxy / SWG como sustituto.
- Esta hipótesis NO cubre el caso donde el operador NO registra device y se limita a session-cookie reuse: para eso, ver `aitm_chain_correlation.kql` con anchor en risky sign-in + inbox rule.
