---
date: 2026-10-28
title: "Huntress: a ten-week Microsoft 365 token spray and replay campaign from 1337 Services hosts ends in rogue Entra devices, wiped MFA and BEC inbox rules"
clusters: ["Unattributed (1337 Services GmbH infrastructure)"]
cluster_country: "Unattributed"
techniques_enterprise: [T1557, T1566.002, T1528, T1550.001, T1078.004, T1110.003, T1090.003, T1098.005, T1556.006, T1564.008, T1114.003, T1534]
techniques_ics: []
platforms: [cloud-multi]
sectors: [cross-sector]
category: identity-cloud
---

# Huntress: a ten-week Microsoft 365 token spray and replay campaign from 1337 Services hosts ends in rogue Entra devices, wiped MFA and BEC inbox rules

## TL;DR

Huntress (post dated 2026-10-22) describes a Microsoft 365 campaign that ran from 2026-07-14 to 2026-09-22 against 79 organizations: over 200,000 failed sign-ins and at least 497 successful ones, replayed from a small block of hosting addresses (193.26.115.0/24, AS210558, 1337 Services GmbH). Tokens were captured through adversary-in-the-middle relays, device-code phishing and social engineering at legitimate logins, then replayed 4 to 12 minutes after the victim reached the MFA prompt. The actor registered at least 48 rogue Entra devices, wiped and replaced MFA methods (19 organizations within three hours), hid mail with punctuation-named inbox rules and, in one case, sent a payroll-themed message to an outside CPA. It matters today because a password reset alone leaves devices, MFA methods and the access token (about 90 minutes) in place, and because Conditional Access visibly worked in the heaviest-sprayed tenants. No actor is named.

## Attribution and confidence

- **Cluster:** none named by Huntress. The only anchor is infrastructure: replay hosts in 193.26.115.0/24 at 1337 Services GmbH (Hamburg), described as bring-your-own-IP hosting, plus an Evoxt Sdn. Bhd. relay in the final takeover. Huntress cites a February 2025 Krebs on Security article suggesting the company's founder may have run the Cracked forum; that is context about the host, not about the customer using it.
- **Vendor and date:** Huntress, 2026-10-22 (Andrea Hatcher, Susannah Matt, Matt Poto, Andrew Schwartz).
- **Confidence:** campaign cohesion **high** (shared infrastructure, tooling builds, client IDs and persistence patterns across 79 organizations); actor attribution **low** (none made).

| Attribute | Build A (scripted) | Build B (browser) |
|---|---|---|
| Hosts | 193.26.115.221, .16, .21, .72 | 193.26.115.199, .210 |
| User agent | `node`, or bare `Mozilla/5.0` (on .21) | Current Chrome or Edge on Windows |
| Request types | `OAuth2:Token` | `Login:reprocess`, `OAuth2:Authorize` |
| Client app | Microsoft Office, Authentication Broker | OfficeHome |
| Targets | Graph, Exchange, SharePoint, Device Registration Service | OfficeHome, Exchange |

**Genealogy in this repo:** the 2026-10-05 TA419 case also steals Microsoft sessions with a frameless browser-in-the-browser AiTM page; this campaign shows the same session-theft step industrialised and followed by persistence and BEC. No overlap in infrastructure or actor is claimed.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| 1. Token capture | T1557, T1566.002, T1528 | AiTM relays, device-code phishing, social engineering during legitimate logins |
| 2. Token replay | T1550.001, T1078.004, T1090.003 | Replay from 1337 Services hosts; Build A scripted, Build B browser |
| 3. Spray and validity | T1110.003 | 200,000+ failures; AADSTS53003 marks a valid credential stopped by Conditional Access |
| 4. Rogue devices | T1098.005 | 48+ devices named DESKTOP- plus eight hex characters via Device Registration Service |
| 5. MFA replacement | T1556.006 | Methods wiped and re-registered; new method within three hours in 19 organizations |
| 6. Hiding rules | T1564.008, T1114.003 | One-to-three-character or punctuation names; moves to RSS and Conversation History folders |
| 7. BEC follow-on | T1534 | Spam from compromised mailbox; payroll-themed message to an outside CPA |

![Huntress M365 token replay kill chain](./kill_chain.svg)

The left lane follows the victim account from token capture to mail abuse; the right lane holds attribution, the four campaign phases, Conditional Access lessons, the indicators with their limits and the response order. Detection anchors are the published address block, a scripted user agent on the Office or Broker client IDs, DESKTOP-hex devices, MFA delete-then-register pairs and hiding rules.

## Stage-by-stage detail

### 1. Token capture (T1557, T1566.002, T1528)

Huntress reports three capture routes: adversary-in-the-middle relays, device-code phishing and social engineering during a legitimate login. The device-code and broker sign-ins carry the request type `Cmsi:Cmsi` (phase 2). Captured material is a session or refresh grant, so MFA completed by the user does not protect it.

### 2. Token replay (T1550.001, T1078.004, T1090.003)

Stolen sessions were replayed from 1337 Services hosts. The gap between the victim reaching the MFA prompt and the hijacked session was 12 minutes on 2026-07-21 and 4 minutes on 2026-09-22. In August one organization saw three failed replays of the same session, all `AADSTS50133` (SsoArtifactRevoked).

```text
Phase 1  2026-07-14 to 08-03   193.26.115.221 (A), .199 (B)    37 orgs signed in, 37 rogue devices
Phase 2  from 2026-08-17       193.26.115.16, .21              device-code phishing, MFA wipes, SharePoint access
Phase 3  2026-09-11 to ~09-15  193.26.115.72                   303 successes in 29 orgs (one section) / 232 in 28 (another)
Phase 4  2026-09-02 to 09-22   193.26.115.210 + Evoxt relay    final takeover 2026-09-22
```

The post gives two different counts for phase 3; this write-up treats both as approximate.

```text
Client apps : d3590ed6-52b3-4102-aeff-aad2292ab01c (Office)  29d9ed98-a469-4536-ade2-f981bc1d605e (Broker)  4765445b-32c6-49b0-83e6-1d93765276ca (OfficeHome)
Resources   : 00000003-0000-0000-c000-000000000000 (Graph)  00000002-0000-0ff1-ce00-000000000000 (Exchange)
              00000003-0000-0ff1-ce00-000000000000 (SharePoint)  01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 (Device Registration Service)
```

### 3. Spray volume versus a valid credential (T1110.003)

The campaign included heavy spraying (1,052 blocked sign-ins from four organizations in phase 3). Huntress argues that the high-volume tenants were often the ones where Conditional Access worked, and tells responders to prioritise by credential validity: an `AADSTS53003` (BlockedByConditionalAccess) proves the password or session was good.

### 4. Rogue Entra devices (T1098.005)

At least 48 rogue Entra-joined devices were created through the Device Registration Service using the Authentication Broker client. Names are `DESKTOP-` plus eight uppercase hex characters (`DESKTOP-54521F46`, `DESKTOP-BAF88EF4`, `DESKTOP-CA85907C`); the Windows default is seven alphanumeric characters. Huntress warns the pattern is not unique to this campaign, so confirm before deleting.

### 5. MFA methods wiped and replaced (T1556.006)

Existing methods were wiped and replaced; in 19 organizations a new method appeared within three hours of the first campaign sign-in, and on the 2026-07-21 account an attacker authenticator was labelled "iPhone 13". The new method survives a password reset.

### 6. Hiding inbox rules (T1564.008, T1114.003)

| Name | Action | Trigger |
|---|---|---|
| `.`, `sss` | Mark as read, delete | All mail |
| `ss` | Move to RSS Feeds, mark read | A business partner's domain |
| `iT`, `,.` | Move to Conversation History, mark read | All mail |
| `........` | Move to RSS Subscriptions, mark read | All mail |
| `s` | Hide | Payroll, direct deposit, bank, bonus |
| `d` | Move to Conversation History, mark read | One external CPA |

Four mailboxes had rules created through the Outlook REST API rather than the Outlook client. Rule-creation sources were commercial VPNs and hosting (ExpressVPN, NordVPN, CrownCloud, DataWagon, GLOBALTELEHOST, LeaseWeb, Dynu, Interserver), none from 1337 Services, so the rule step comes from different addresses than the replay.

### 7. BEC follow-on (T1534)

Huntress observed spam sent from a compromised mailbox and, in one incident, a payroll-themed email to an outside CPA, after a rule hid payroll and bank mail. The post reports no confirmed financial loss.

## Detection strategy

### Telemetry that matters

- Entra `SigninLogs` and `AADNonInteractiveUserSignInLogs` (IPAddress, AppId, UserAgent, ResultType, request type). Retain non-interactive logs: Build A lives there.
- Entra `AuditLogs`: Add device, security info deleted or registered, consent grants and new enterprise applications.
- Exchange admin audit / `CloudAppEvents`: `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, with `UserAgent` to separate Outlook REST API from the client.
- Conditional Access result details and `AADSTS` codes in sign-in logs.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [01_entra_signin_from_1337_services_replay_hosts.yml](./sigma/01_entra_signin_from_1337_services_replay_hosts.yml) | Sign-in from 193.26.115.0/24 or related addresses |
| Sigma | [02_entra_signin_node_useragent_office_or_broker_app.yml](./sigma/02_entra_signin_node_useragent_office_or_broker_app.yml) | Office or Broker app with `node` or bare `Mozilla/5.0` |
| Sigma | [03_entra_device_registered_with_desktop_hex_name.yml](./sigma/03_entra_device_registered_with_desktop_hex_name.yml) | Device named DESKTOP- plus eight hex characters |
| Sigma | [04_entra_user_security_info_deleted_mfa_method_wipe.yml](./sigma/04_entra_user_security_info_deleted_mfa_method_wipe.yml) | MFA method deleted or registered (pair in SIEM) |
| Sigma | [05_exchange_inbox_rule_hides_mail_short_name_or_payroll_keywords.yml](./sigma/05_exchange_inbox_rule_hides_mail_short_name_or_payroll_keywords.yml) | Hiding folders or payroll keywords in an inbox rule |
| KQL | [k1](./kql/k1_token_replay_signins_from_published_hosts_and_scripted_clients.kql) | Published hosts, scripted clients, CA-blocked valid credentials |
| KQL | [k2](./kql/k2_rogue_desktop_hex_devices_and_mfa_wipe_reregister_pairs.kql) | Rogue devices and MFA delete-then-register within three hours |
| KQL | [k3](./kql/k3_inbox_rules_hiding_mail_and_payroll_keywords.kql) | Short or punctuation rule names, hiding folders, keywords |
| YARA | [m365_token_replay_evidence_markers.yar](./yara/m365_token_replay_evidence_markers.yar) | Two rules over exported sign-in and rule data (no sample exists) |
| Suricata | [m365_token_replay_network.rules](./suricata/m365_token_replay_network.rules) | sids 6450001-6450003; network sees little, logs are primary |

### Threat hunting hypotheses

- **H1** — replayed sessions from hosting infrastructure with scripted clients: [peak_h1_token_replay_signins.md](./hunts/peak_h1_token_replay_signins.md)
- **H2** — rogue Entra devices, MFA swaps and new enterprise applications: [peak_h2_rogue_devices_mfa_and_apps.md](./hunts/peak_h2_rogue_devices_mfa_and_apps.md)
- **H3** — hiding inbox rules and the payroll or BEC follow-on: [peak_h3_bec_inbox_rules_and_payroll.md](./hunts/peak_h3_bec_inbox_rules_and_payroll.md)

## Incident response playbook

### First 60 minutes (triage)

1. Revoke all sessions for the affected user (Revoke-MgUserSignInSession) before anything else; a reset alone does not kill the token.
2. Reset the password and require re-registration of MFA from a trusted network.
3. List and remove unknown authentication methods and Entra devices; confirm owners first.
4. List inbox rules, forwarding and delegates; delete hiding rules and note their creation time and IP.
5. Warn payroll, finance and external accountants contacted from the mailbox; freeze payment-detail changes until verified by phone.
6. Preserve sign-in, audit and mailbox audit logs before retention expires.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Interactive and non-interactive sign-ins | Entra sign-in logs | Graph / Sentinel export | Replay hosts, user agents, request types, AADSTS codes |
| Device registrations | Entra audit logs, Devices blade | Graph | Rogue DESKTOP-hex devices and registering IP |
| Authentication methods | Entra user auth methods | Graph | Wiped and attacker-registered methods |
| Inbox rules and mailbox audit | Exchange Online | Exchange PowerShell, Purview | Hiding rules, REST API creation, sent items |
| App consents | Entra enterprise applications | Graph | New apps and user consent grants |

### IR queries and commands

```powershell
# Author: Jarmi
Connect-MgGraph -Scopes "User.ReadWrite.All","Device.Read.All","UserAuthenticationMethod.Read.All"
$u = "user@contoso.com"
Revoke-MgUserSignInSession -UserId $u
Get-MgUserAuthenticationMethod -UserId $u | Format-List
Get-MgUserRegisteredDevice -UserId $u | Select-Object Id, DisplayName
Get-MgDevice -All | Where-Object { $_.DisplayName -match '^DESKTOP-[0-9A-F]{8}$' } | Select-Object DisplayName, RegistrationDateTime, Id
Get-InboxRule -Mailbox $u | Select-Object Name, Enabled, MoveToFolder, MarkAsRead, DeleteMessage, SubjectOrBodyContainsWords
```

### Containment, eradication, recovery

- **Exit criteria:** sessions revoked, unknown devices and methods removed, hiding rules deleted, no new sign-ins from the published block or from the user's old session, finance confirmed no payment-detail change.
- **Fix the policy:** require MFA or block for all users, all cloud apps and all client app types without exceptions; restrict the device-code flow; disable user consent and require admin review of apps.
- **Do not:** reset the password and stop there; delete a device only because its name matches (confirm first); rely on blocking one address, since the actor rotated them.

### Recovery validation

Re-run H1 to H3 for 14 days after containment; confirm no new DESKTOP-hex devices, no new MFA registrations from unfamiliar IPs and no new hiding rules.

## IOCs

Top rows below; full list in [iocs.csv](./iocs.csv). This case has no CVE, so no KEV status applies.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| note | 193.26.115.0/24 | Six main replay hosts, AS210558 1337 Services GmbH | medium | Huntress |
| ipv4 | 193.26.115.221 | Replay host, Build A, phase 1 | medium | Huntress |
| ipv4 | 193.26.115.199 | Replay host, Build B, phase 1 | medium | Huntress |
| ipv4 | 193.26.115.16 | Replay host, Build A, phase 2 | medium | Huntress |
| ipv4 | 193.26.115.21 | Replay host, bare Mozilla/5.0 | medium | Huntress |
| ipv4 | 193.26.115.72 | Replay host, phase 3 | medium | Huntress |
| ipv4 | 193.26.115.210 | Replay host, Build B, phase 4 | medium | Huntress |
| ipv4 | 124.198.132.33 | Additional 1337 Services address | medium | Huntress |
| ipv4 | 185.238.2.195 | Relay address, 2026-07-21 | medium | Huntress |
| string | d3590ed6-52b3-4102-aeff-aad2292ab01c | Office client ID, Build A | high | Huntress |
| string | 29d9ed98-a469-4536-ade2-f981bc1d605e | Authentication Broker client ID | high | Huntress |
| string | 4765445b-32c6-49b0-83e6-1d93765276ca | OfficeHome client ID, Build B | high | Huntress |
| string | DESKTOP-54521F46 | Example rogue device name | medium | Huntress |
| string | AADSTS53003 | Valid credential blocked by Conditional Access | medium | Huntress |
| string | inbox-rule-name:sss | Hiding rule name | medium | Huntress |

These are infrastructure indicators from July to September 2026 and decay quickly: re-validate before blocking.

## Secondary findings

- **Storm-0940 and ARTEX (Microsoft, 2026-10-21):** Microsoft assesses China-state-aligned Storm-0940 used the open-source agentic AI pentest framework ARTEX to automate a password-spray campaign (10-14 October, 151,000+ failed logons against 327 accounts at eight organizations, no successful authentication in that phase) and a ConnectWise multi-tenant app supply-chain compromise, with Graph recon, app credential changes and bulk Key Vault reads at machine speed. IPs include 144.172.64.128, .99 and .60. Taxonomy #18 and #7 candidate.
- **LiteLLM 1.107.0 compromise (Microsoft, 2026-10-23):** a malicious release published on 2026-10-21 stole developer, cloud and SSH credentials through `cook.pth` and `sitecustomize.py` Python startup hooks that run even if LiteLLM is never imported; exfiltration to www[.]litellm[.]dev. Removing the package is not enough: rebuild from verified artifacts and rotate reachable secrets.
- **AI-assisted executive-impersonation invoice fraud (Microsoft, 2026-09-10):** more than one million emails impersonating executives and ServiceNow, a fabricated forwarded thread and invoices of nearly $50,000, about 88% of targets in the United States; template structure suggests AI-assisted generation, which Microsoft cannot confirm. This is the BEC end of the same fraud economy.

## Pedagogical anchors

- MFA protects the login, not the session: once a token is stolen, the attacker inherits the completed MFA.
- Persistence is the real objective; a password reset that leaves devices and MFA methods behind is not containment.
- Prioritise by credential validity: an `AADSTS53003` in the logs is a confirmed compromised password even though the attack failed.
- Business email compromise is an identity incident first: detect the hiding rule and the preceding sign-in as one story.
- Retain and query the non-interactive sign-in logs; the scripted replay tooling lived there.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This case write-up. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram. | [kill_chain.svg](./kill_chain.svg) |
| sigma/ | Five Sigma rules for Entra sign-ins, devices, MFA and inbox rules. | [sigma/](./sigma/) |
| kql/ | Three Sentinel and Defender XDR queries. | [kql/](./kql/) |
| yara/ | Two rules for exported evidence. | [yara/](./yara/) |
| suricata/ | Three network rules (sids 6450001-6450003). | [suricata/](./suricata/) |
| hunts/ | Three PEAK hunts H1-H3. | [hunts/](./hunts/) |
| iocs.csv | Full indicator list (41 rows). | [iocs.csv](./iocs.csv) |

## Sources

- [Huntress - M365 token spray and replay campaign (2026-10-22)](https://www.huntress.com/blog/token-replay-spray)
- [Microsoft - Storm-0940 uses ARTEX agentic AI in ConnectWise supply chain compromise (2026-10-21)](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
- [Microsoft - Inside the LiteLLM 1.107.0 supply chain compromise (2026-10-23)](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
- [Microsoft - Protecting organizations from AI-assisted executive impersonation invoice fraud (2026-09-10)](https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/)
- [The Record - Microsoft sees some new wrinkles in invoice-scam emails](https://therecord.media/invoice-scam-emails-new-features-microsoft-researchers)
- [The Defensive Line Weekly, episode 41 (18-25 October 2026)](https://thedefensiveline.substack.com/p/the-defensive-line-weekly-episode-c12)
