---
date: 2026-05-06
title: "Code of Conduct AiTM — Tycoon2FA-class campaign, PRT post-AiTM persistence (Storm-1747)"
clusters:
  - "Storm-1747"
  - "Tycoon2FA"
  - "Storm-1575"
  - "Dadsec"
cluster_country: "e-crime (PhaaS — operadores y afiliados varios)"
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

**Cluster operativo:** Storm-1747 (Tycoon2FA PhaaS) — atribución por *kit fingerprint*, no por afiliado-operador (Tycoon2FA es panel-as-a-service, $120 USD / 10 días, $350 / mes).
**Eco-actor relacionado:** Storm-1575 (Dadsec) — comparte infraestructura con Tycoon2FA.
**Confianza atribución de familia:** Media-alta. Confianza del afiliado: baja.
**Origen del informe:** [Microsoft Security Blog — 4-may-2026](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/).

## Resumen ejecutivo

Entre el 14 y 16 de abril de 2026, una campaña de phishing temática "código de conducta" alcanzó a **>35.000 usuarios en >13.000 organizaciones** repartidas en **26 países**, con el **92% de víctimas en EE.UU.** y carga sectorial concentrada en *healthcare & life sciences* (19%), *financial services* (18%), *professional services* (11%) y *technology & software* (11%). El payload primario es un **PDF adjunto** (`Awareness Case Log File - Tuesday 14th, April 2026.pdf` / `Disciplinary Action - Employee Device Handling Case.pdf`) con un botón "Review Case Materials" que enlaza a una landing AiTM gateada por **Cloudflare CAPTCHA** (anti-sandbox), seguida de un **reverse-proxy phishing** contra `login.microsoftonline.com`. Tras la captura de cookies + tokens, los operadores **registran un device nuevo en menos de 10 minutos** sobre la cuenta víctima ⇒ generan **Primary Refresh Token (PRT)** ⇒ persistencia que *sobrevive a la rotación de contraseña*. Otras víctimas reciben **inbox rules** (BEC) horas después.

## Atribución y línea base de Tycoon2FA

- **Storm-1747** desarrolla y vende Tycoon2FA en Telegram + Signal desde agosto de 2023.
- En 2025-2026, Tycoon2FA es la PhaaS más prolífica observada por Microsoft Defender para Office 365 (>13M correos bloqueados/mes en pico de octubre de 2025).
- Infraestructura migra desde Cloudflare a TLDs baratos (`.de`, `.space`, `.email`, `.solutions`, `.live`, `.today`, `.calendar`) con FQDNs de **24-72h** de vida.
- Salty2FA y Mamba2FA son reemulaciones / híbridos del kit observados por ANY.RUN y Trustwave.

## Kill chain (resumen — detalle en clase principal)

| Stage | MITRE | Detalle |
|---|---|---|
| Resource Dev | T1583.001 / T1608.005 | Compra dominios `.de` con keywords (acceptable-use-policy-calendly[.]de, compliance-protectionoutlook[.]de) |
| Initial Access | T1566.001 / T1566.002 | PDF adjunto temático con `/A /URI` apuntando a landing |
| Execution | T1204.001/.002 | User pulsa "Review Case Materials" → CAPTCHA Turnstile → "Sign in with Microsoft" |
| Credential Access | T1557, T1539, T1606.001 | Reverse-proxy AiTM captura ESTSAUTH + access_token + refresh_token |
| **Persistence** | **T1098.005** ⭐ | **Device join < 10 min → PRT forging** |
| Defense Evasion | T1078.004, T1564.008 | Cloud account valid; reglas de inbox con nombre invisible |
| Collection | T1114.002/.003 | Forwarding rules + Graph `/me/messages` |
| Impact | T1657 | BEC: invoice fraud / wire redirection |

## Por qué este caso es pedagógicamente relevante

1. **MFA TOTP/SMS/push NO mitigan** — el proxy AiTM bypasea por diseño. Sólo **FIDO2/passkeys/WebAuthn** rompen el ataque (clave atada al *origin*).
2. **Cambiar la contraseña NO basta** — el PRT del device fraudulento sobrevive. **Hay que eliminar el device de Entra ID**.
3. **El click-out del PDF es el único IOC inicial** — el PDF es benigno en sandbox; sólo la URL es maliciosa.
4. La *correlación temporal* `risky-signin → device-add < 1h → inbox-rule < 24h` es la firma operacional del kit.

## What's in this folder

| Archivo | Propósito |
|---|---|
| [`README.md`](./README.md) | Este documento |
| [`sigma/code_of_conduct_aitm_pdf_lure.yml`](./sigma/code_of_conduct_aitm_pdf_lure.yml) | PDF lure (M365 EmailEvents) |
| [`sigma/entra_id_device_register_post_signin.yml`](./sigma/entra_id_device_register_post_signin.yml) | Device register sospechoso (AuditLogs) |
| [`sigma/inbox_rule_invisible_name.yml`](./sigma/inbox_rule_invisible_name.yml) | Inbox rule con nombre 1-char (BEC) |
| [`kql/aitm_chain_correlation.kql`](./kql/aitm_chain_correlation.kql) | Correlación signin + device-add + inbox rule (24h) |
| [`kql/firstseen_attacker_domain_pdf.kql`](./kql/firstseen_attacker_domain_pdf.kql) | PDF + first-seen domain click-through |
| [`kql/peak_h1_click_to_device.kql`](./kql/peak_h1_click_to_device.kql) | PEAK H1 hunt — click → device join 2h |
| [`spl/inbox_rule_invisible_name.spl`](./spl/inbox_rule_invisible_name.spl) | SPL — inbox rule one-char name |
| [`yara/CodeOfConduct_AiTM_PDF_Lure_2026.yar`](./yara/CodeOfConduct_AiTM_PDF_Lure_2026.yar) | Heurística sobre el PDF lure |
| [`suricata/code_of_conduct_aitm_landing.rules`](./suricata/code_of_conduct_aitm_landing.rules) | Suricata 7.x — TLS SNI / HTTP host hacia dominios attacker |
| [`hunts/peak_h1_aitm_to_device.md`](./hunts/peak_h1_aitm_to_device.md) | PEAK H1 hunt write-up |
| [`iocs.csv`](./iocs.csv) | IOCs validados |

## Sources

- [Microsoft Security Blog — Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise (4-may-2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)
- [Microsoft Security Blog — Inside Tycoon2FA (4-mar-2026)](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- [Microsoft Security Blog — Email threat landscape: Q1 2026 trends and insights (30-abr-2026)](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/)
- [The Hacker News — Microsoft Details Phishing Campaign Targeting 35,000 Users Across 26 Countries](https://thehackernews.com/2026/05/microsoft-details-phishing-campaign.html)
- [Help Net Security — Microsoft: Phishing campaign used fake compliance notices](https://www.helpnetsecurity.com/2026/05/05/microsoft-phishing-fake-compliance-notices/)
- [MITRE ATT&CK — T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE ATT&CK — T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK — T1564.008 Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)

— Jarmi
