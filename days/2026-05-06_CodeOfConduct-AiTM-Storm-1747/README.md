---
date: 2026-05-06
title: "Code of Conduct AiTM — Tycoon2FA-class campaign, PRT post-AiTM persistence (Storm-1747)"
clusters:
  - "Storm-1747"
  - "Tycoon2FA"
  - "Storm-1575"
  - "Dadsec"
cluster_country: "e-crime (PhaaS — multiple operators and affiliates)"
techniques_enterprise:
  - T1583.001
  - T1608.005
  - T1566.001
  - T1566.002
  - T1204.001
  - T1204.002
  - T1557
  - T1539
  - T1606.001
  - T1098.005
  - T1078.004
  - T1564.008
  - T1114.002
  - T1114.003
  - T1071.001
  - T1657
platforms:
  - cloud-multi
  - supply-chain
sectors:
  - healthcare
  - finance
  - professional-services
  - technology
---

# Code of Conduct AiTM — Tycoon2FA-class campaign, PRT post-AiTM persistence

**Operator cluster:** Storm-1747 (Tycoon2FA PhaaS) — attribution by *kit fingerprint*, not by individual affiliate (Tycoon2FA is a panel-as-a-service, $120 USD / 10 days, $350 USD / month).
**Related actor:** Storm-1575 (Dadsec) — shares infrastructure with Tycoon2FA.
**Family attribution confidence:** Medium-high. Affiliate operator confidence: low.
**Primary report:** [Microsoft Security Blog — 4-may-2026](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/).

## Executive summary

Between **April 14 and 16, 2026**, a "code of conduct"-themed phishing campaign reached **>35,000 users in >13,000 organizations** across **26 countries**, with **92% of victims in the United States** and the heaviest sector load on *healthcare & life sciences* (19%), *financial services* (18%), *professional services* (11%) and *technology & software* (11%). The primary payload is a **PDF attachment** (`Awareness Case Log File - Tuesday 14th, April 2026.pdf` / `Disciplinary Action - Employee Device Handling Case.pdf`) carrying a "Review Case Materials" button that links to an AiTM landing page gated by a **Cloudflare CAPTCHA** (anti-sandbox), followed by a **reverse-proxy phishing flow** against `login.microsoftonline.com`. After cookies + tokens are captured, operators **register a new device in less than 10 minutes** on the victim account, derive a **Primary Refresh Token (PRT)**, and gain persistence that *survives password rotation*. Other victims receive **inbox rules** (BEC) hours later.

## Attribution and Tycoon2FA baseline

- **Storm-1747** has developed and sold Tycoon2FA on Telegram + Signal since August 2023.
- During 2025–2026, Tycoon2FA is the most prolific PhaaS observed by Microsoft Defender for Office 365 (>13M malicious emails blocked per month at the October-2025 peak).
- Infrastructure migrated from Cloudflare to cheap TLDs (`.de`, `.space`, `.email`, `.solutions`, `.live`, `.today`, `.calendar`) with **24-72h** FQDNs.
- Salty2FA and Mamba2FA are reemulations / hybrids of the kit observed by ANY.RUN and Trustwave.

## Kill chain (summary — full detail in the lecture file)

| Stage | MITRE | Detail |
|---|---|---|
| Resource Dev | T1583.001 / T1608.005 | Buys `.de` keyword domains (acceptable-use-policy-calendly[.]de, compliance-protectionoutlook[.]de) |
| Initial Access | T1566.001 / T1566.002 | PDF attachment with `/A /URI` action pointing to landing |
| Execution | T1204.001 / T1204.002 | User clicks "Review Case Materials" → CAPTCHA Turnstile → "Sign in with Microsoft" |
| Credential Access | T1557, T1539, T1606.001 | Reverse-proxy AiTM captures ESTSAUTH + access_token + refresh_token |
| **Persistence** | **T1098.005** ⭐ | **Device join < 10 min → PRT forging** |
| Defense Evasion | T1078.004, T1564.008 | Valid cloud account; inbox rules with invisible name |
| Collection | T1114.002 / T1114.003 | Forwarding rules + Graph `/me/messages` |
| Impact | T1657 | BEC: invoice fraud / wire redirection |

## Why this case matters

1. **TOTP/SMS/push MFA do NOT mitigate** — the AiTM proxy bypasses them by design. Only **FIDO2/passkeys/WebAuthn** break the attack (key bound to the *origin*).
2. **Rotating the password is NOT enough** — the PRT bound to the rogue device survives. **The rogue device must be removed from Entra ID.**
3. **The PDF click-out is the only initial IOC** — the PDF itself is benign in sandbox; only the URL is malicious.
4. The temporal correlation `risky-signin → device-add < 1h → inbox-rule < 24h` is the operational signature of the kit.

## What's in this folder

| File | Purpose |
|---|---|
| [`README.md`](./README.md) | This document |
| [`sigma/code_of_conduct_aitm_pdf_lure.yml`](./sigma/code_of_conduct_aitm_pdf_lure.yml) | PDF lure (M365 EmailEvents) |
| [`sigma/entra_id_device_register_post_signin.yml`](./sigma/entra_id_device_register_post_signin.yml) | Suspicious device register (AuditLogs) |
| [`sigma/inbox_rule_invisible_name.yml`](./sigma/inbox_rule_invisible_name.yml) | InboxRule with 1-char or symbol-only name (BEC) |
| [`kql/aitm_chain_correlation.kql`](./kql/aitm_chain_correlation.kql) | signin + device-add + inbox rule correlation (24h) |
| [`kql/firstseen_attacker_domain_pdf.kql`](./kql/firstseen_attacker_domain_pdf.kql) | First-seen attacker domain via PDF attachment |
| [`kql/peak_h1_click_to_device.kql`](./kql/peak_h1_click_to_device.kql) | PEAK H1 hunt — click → device join 2h |
| [`spl/inbox_rule_invisible_name.spl`](./spl/inbox_rule_invisible_name.spl) | SPL — InboxRule one-char name |
| [`yara/CodeOfConduct_AiTM_PDF_Lure_2026.yar`](./yara/CodeOfConduct_AiTM_PDF_Lure_2026.yar) | Heuristic over the PDF lure |
| [`suricata/code_of_conduct_aitm_landing.rules`](./suricata/code_of_conduct_aitm_landing.rules) | Suricata 7.x — TLS SNI / HTTP host to attacker domains |
| [`hunts/peak_h1_aitm_to_device.md`](./hunts/peak_h1_aitm_to_device.md) | PEAK H1 hunt write-up |
| [`iocs.csv`](./iocs.csv) | Validated IOCs |

## Sources

- [Microsoft Security Blog — Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise (4-may-2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)
- [Microsoft Security Blog — Inside Tycoon2FA (4-mar-2026)](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- [Microsoft Security Blog — Email threat landscape: Q1 2026 trends and insights (30-apr-2026)](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/)
- [The Hacker News — Microsoft Details Phishing Campaign Targeting 35,000 Users Across 26 Countries](https://thehackernews.com/2026/05/microsoft-details-phishing-campaign.html)
- [Help Net Security — Microsoft: Phishing campaign used fake compliance notices](https://www.helpnetsecurity.com/2026/05/05/microsoft-phishing-fake-compliance-notices/)
- [MITRE ATT&CK — T1098.005 Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE ATT&CK — T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK — T1564.008 Hide Artifacts: Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)

— Jarmi
