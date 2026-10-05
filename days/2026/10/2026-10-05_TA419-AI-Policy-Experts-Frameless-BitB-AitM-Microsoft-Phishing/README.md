---
date: 2026-10-05
title: "TA419 impersonates AI policy experts: a reply-first lure and a Frameless BitB adversary-in-the-middle page that steals Microsoft sessions"
clusters: ["TA419"]
cluster_country: "China-aligned (per Proofpoint)"
techniques_enterprise: [T1656, T1598, T1583.001, T1583.003, T1588.002, T1566.002, T1204.001, T1557, T1111, T1539, T1550.004, T1078.004]
techniques_ics: []
platforms: [cloud-multi]
sectors: [think-tanks, education, legal-and-professional-services, defense, government]
category: espionage
---

# TA419 impersonates AI policy experts: a reply-first lure and a Frameless BitB adversary-in-the-middle page that steals Microsoft sessions

## TL;DR

Proofpoint published research on 2026-10-01 (page metadata 2026-09-30) on **TA419**, a China-aligned, espionage-motivated cluster that has phished people at US and Japan-based think tanks, defence contractors, universities and law firms since at least April 2025.
Since 8 July 2026 it has impersonated real AI policy figures, among them a former White House OSTP leader and an economist, and in February 2026 a senior Anthropic employee, to invite experts to a fictitious "AI Policy Advisory Committee" or to contribute to a Senate report on AI export controls.
The first email has no link; the shortened URL arrives only after the target replies, and leads through a Cloudflare Turnstile check and a fake OneDrive page to a modified **Frameless BitB** window that relays the real Microsoft sign-in, MFA included, while the actor takes the session cookie.
Proofpoint publishes 23 indicators (3 sender addresses, 15 phishing domains, 4 lookalike sender domains and a TLS certificate hash) but no victim count and no post-compromise activity, so this is a case about the lure and the sign-in, not about what the actor did next.
The lesson for today: MFA that a proxy can relay does not stop the page, and the Entra session ID is the thread that shows the theft.

## Attribution and confidence

**Cluster:** TA419 (Proofpoint's tracking name). **Aliases:** none published; Proofpoint maps it to no other vendor's name. **Vendor and date:** Proofpoint, 2026-10-01 (page metadata shows 2026-09-30). **Confidence:** the type of actor (China-aligned, espionage-motivated) is Proofpoint's judgement, worded as the activity "likely supports wider Chinese intelligence objectives". Proofpoint gives no separate confidence level and names no agency. Rated here: attribution to a state agency **low**, the description of the activity itself **high**, because the indicators and the kit behaviour come from the vendor's own telemetry.

| Item | Proofpoint says | Other sources |
|---|---|---|
| Actor type | China-aligned, espionage-motivated; first public report of this activity | CyberScoop: the report does not directly link the activity to the Chinese government; China has repeatedly denied cyber espionage |
| Start of activity | At least April 2025 (credential phishing against US and Japan targets) | Consistent in The Hacker News, IT Pro, CyberScoop |
| AI-policy campaigns | February 2026 (Anthropic persona) and from 8 July 2026 (former-official personas) | IT Pro calls it a "July 2026 report", which does not match the Proofpoint page |
| Related cluster | UNK_SweetSpecter, China-aligned, AI-themed phishing: described as separate | IT Pro: about two years earlier, targeting generative-AI organisations |
| Victim count | Not stated | CSA research note cites a Technology.org report of fewer than ten individuals; not fetched or confirmed |

**Source conflicts, listed and not resolved.** The report date differs (2026-09-30 in the Proofpoint metadata, 2026-10-01 in its byline and in CyberScoop, 2026-10-02 in IT Pro, 2026-10-04 in The Hacker News). Proofpoint names the persona "Lynne Edwards Parker"; other outlets write "Lynne Parker". CyberScoop says domains resembling the World Economic Forum were registered; that name is not in the Proofpoint indicator table that was reviewed. IT Pro attributes quotes to the Proofpoint analyst Mark Kelly that could not be matched to the Proofpoint page, so they are not quoted here.

**Source handling.** The Proofpoint post was read through a summarising fetch tool, not in a browser, so the script behaviour and the indicator table below are as extracted and should be checked against the original page before they feed a block list. The CSA research note is a secondary analysis; where it adds its own inference, the text says so.

**Genealogy with this repo.** Adversary-in-the-middle phishing of Microsoft 365 appears in [Payroll Pirates](../../08/2026-08-12_PayrollPirates-Storm2755-AiTM-M365-Graph-Mailbox-Collection/README.md) (financial fraud), [CaptiveCrunch](../../08/2026-08-10_CaptiveCrunch-MidnightBlizzard-CaptivePortal-AitM/README.md) (captive-portal lures) and [ARToken](../../07/2026-07-22_ARToken-EvilTokens-BEC-DeviceCode-InboxRule-PhaaS/README.md) (device-code phishing as a service). This case is the espionage version: the same session theft, a different motive, and a lure built on a person's reputation rather than on an invoice.

## Kill chain — summary table

| Stage | MITRE | Detail |
|---|---|---|
| 1. First contact | T1656, T1598 | Benign invitation from an impersonated expert; no link, no attachment |
| 2. Reply-first gate | T1566.002, T1583.003 | The target replies, then a shortened URL arrives; mail from VPS hosts and some residential proxies |
| 3. Redirect chain | T1204.001, T1583.001 | First-stage domain behind Cloudflare, Turnstile check, fake OneDrive loading screen, then a second-stage domain |
| 4. Frameless BitB window | T1557, T1588.002 | Fake browser window built in HTML, CSS and JavaScript over a fake OneDrive listing |
| 5. AitM relay | T1557, T1111 | Real Microsoft authorize flow with injected scripts; MFA and one-time codes relayed |
| 6. Session capture | T1539 | Session cookie taken after the relayed sign-in; victim sees a normal sign-in |
| 7. Replay and follow-on | T1550.004, T1078.004 | Not described by Proofpoint; a stolen session works until revoked |

![TA419 AI-policy phishing kill chain](./kill_chain.svg)

The left lane follows the target from the first email to the stolen session; stages 4 to 6 are red because that is where credentials and the session leave the user's control. The right lane holds what Proofpoint published about the operator: personas, sending servers, the domain list, the kit, the telemetry module and the attribution wording. The earliest detection anchor is the sender, because the first email has nothing else to score; the strongest later anchor is the Entra session ID used from a second network.

## Stage-by-stage detail

### Stage 1: first contact from an impersonated expert

Proofpoint reports that the actor writes as real, well-known people. In July 2026 the senders were `leparker@mail[.]com` (impersonating Lynne Edwards Parker, described as a former Principal Deputy Director of the White House Office of Science and Technology Policy), `hcrediker@mail[.]com` and `hcrediker@outlook[.]com` (impersonating the economist Heidi Crebo-Rediker). In February 2026 the persona was an unnamed senior Anthropic employee, the recipient was an AI policy analyst at a US think tank and the subject line was "Request for Feedback on Military Integration of Claude". The July pretexts were an invitation to a fictitious "AI Policy Advisory Committee" and a request to contribute to a Senate Committee on Foreign Relations report on AI export controls and supply chains. Proofpoint also lists lookalike sender domains that spoof the Japan-Taiwan Exchange Association (`tw-koryu[.]org`), The Heritage Foundation (`heritiages[.]org`, `heritiage[.]org`) and the official site of Shinjiro Koizumi (`shinjirou[.]info`).

```text
Subject (Feb 2026): Request for Feedback on Military Integration of Claude
Senders (Jul 2026): leparker@mail[.]com  hcrediker@mail[.]com  hcrediker@outlook[.]com
Link in the first email: none
```

MITRE: T1656 Impersonation; T1598 Phishing for Information.

### Stage 2: the reply-first gate

The first message is benign and carries no link; the shortened URL is sent only after the recipient replies. Proofpoint says first-hop Received headers showed VPS hosts, with one example at `108.61.163[.]187`, presenting a shared self-signed TLS certificate on a high ephemeral port, and that some emails went through residential proxy services. The certificate subject is `C=US, ST=Kansas, L=Millsstad, O=Castro Inc, CN=CI` and its SHA-256 is `b314a1499cd728ca3e54b7150661fd0c7d2279065fe3f570f0f66c395d744460`, first seen February 2026. The effect is that the link filter has nothing to score at first contact, and that the second message arrives inside an existing conversation.

MITRE: T1566.002 Spearphishing Link; T1583.003 Virtual Private Server.

### Stage 3: redirect chain, Turnstile and the fake OneDrive screen

The shortened URL starts a multi-stage redirect. The first-stage actor domain (Proofpoint's example is `driftshare[.]co`) shows a fake OneDrive loading screen behind a Cloudflare Turnstile check, which Proofpoint describes as an initial filter and which the CSA note reads as an obstacle to automated URL scanning (the note's inference). The second-stage domain (example `globalfileshareplatform[.]com`) hosts the adversary-in-the-middle page. Proofpoint's table lists eight first-stage and seven second-stage domains first seen between December 2025 and July 2026; the domains are file-sharing and cloud-service themes, mostly registered through NameSilo and fronted by Cloudflare. Proofpoint labels each domain by stage and gives one explicit pair; pairing the others by month would be an inference.

MITRE: T1204.001 Malicious Link; T1583.001 Domains.

### Stage 4: the Frameless BitB window

The kit is a modified version of **Frameless BitB**, an open-source browser-in-the-browser project by Wael Masri (January 2024) that builds a fake browser window from HTML, CSS and JavaScript without an iframe. According to Proofpoint it is combined with an Evilginx phishlet for Microsoft 365 and server-side substitution rules. Its description of the page scripts:

```text
/secondary/script.js   Frameless BitB driver. Builds a Shadow DOM with a fake OneDrive folder listing.
                       The documents sit in an attacker OneDrive, reached through a proxy path that turns a
                       1drv.ms share link into a same-origin page. Loads /primary/script.js.
/primary/script.js     Adapted from Frameless BitB. Hooks click and touch events, watches for OneDrive's
                       permission-denied banner, then raises a fake Chrome sign-in window.
```

MITRE: T1557 Adversary-in-the-Middle; T1588.002 Obtain Capabilities: Tool (an open-source kit adapted by the operator).

### Stage 5: relay to the real Microsoft sign-in

The page proxies the real Microsoft `/common/oauth2/v2.0/authorize` flow, with scripts injected into the response, and targets the first-party OfficeHome application, client ID `4765445b-32c6-49b0-83e6-1d93765276ca`. Password, MFA and conditional-access checks pass to Microsoft, so the sign-in the identity provider records is genuine. A custom module, `/secondary/observe.js`, tracks the victim's position in the sign-in, gives the operator a live session view, accepts the "Keep me signed in" prompt and submits one-time codes automatically once validated. The CSA note reads the code automation as a sign that the operator expects code-based or push factors (its inference, not Proofpoint's).

MITRE: T1557 Adversary-in-the-Middle; T1111 Multi-Factor Authentication Interception.

### Stage 6: session capture

The proxy captures the session cookie after the relayed sign-in succeeds; The Hacker News adds that the victim sees a normal, successful sign-in. CyberScoop notes that MFA was not described as bypassed: victims complete it, and the attacker captures the result.

MITRE: T1539 Steal Web Session Cookie.

### Stage 7: replay and follow-on (not reported)

None of the four sources reviewed says what the actor did with the sessions, whether any account was compromised, or how many people were targeted. A stolen session can be replayed until it is revoked and a password reset does not end it (CSA note, general principle); the checks in the playbook assume that exposure is possible and do not claim it happened.

MITRE: T1550.004 Web Session Cookie; T1078.004 Cloud Accounts (as the possible result, not an observed fact).

## Detection strategy

### Telemetry that matters

- **Email:** `EmailEvents` (sender, display name, recipient, delivery action), `EmailUrlInfo`, `UrlClickEvents` in Defender XDR; the raw `.eml` headers for the first-hop Received line.
- **Identity:** Entra `SigninLogs` (interactive, with `AppId`, `AuthenticationRequirement`, `SessionId`, IP and ASN) and `AADNonInteractiveUserSignInLogs`, which is where a replayed session shows up.
- **Network:** DNS, proxy and secure-web-gateway logs for the 15 phishing domains and the three kit paths (the paths need TLS inspection); Zeek `x509` or Suricata TLS logs for the certificate subject.
- **Endpoint:** `DeviceNetworkEvents` for `RemoteUrl`, and the browser history of any user who replied.
- **Audit:** the Microsoft Purview unified audit log for mail and file access after a suspect sign-in.

### Detection coverage

| Engine | File | Logic |
|---|---|---|
| Sigma | [01_ta419_dns_query_to_phishing_and_lookalike_domains.yml](./sigma/01_ta419_dns_query_to_phishing_and_lookalike_domains.yml) | DNS query for any of the 19 published domains, exact or sub-domain |
| Sigma | [02_ta419_proxy_request_to_phishing_domains.yml](./sigma/02_ta419_proxy_request_to_phishing_domains.yml) | Proxy request to a first-stage or second-stage host |
| Sigma | [03_ta419_bitb_kit_script_paths_in_proxy_logs.yml](./sigma/03_ta419_bitb_kit_script_paths_in_proxy_logs.yml) | `/secondary/observe.js`, or the script pair, from a non-Microsoft host |
| Sigma | [04_ta419_shared_self_signed_tls_certificate_subject.yml](./sigma/04_ta419_shared_self_signed_tls_certificate_subject.yml) | Zeek x509 subject containing `Castro Inc` and `Millsstad` |
| KQL | [k1_ta419_senders_sender_domains_and_urls_in_email.kql](./kql/k1_ta419_senders_sender_domains_and_urls_in_email.kql) | Published senders, lookalike domains and phishing URLs in inbound mail |
| KQL | [k2_ta419_domains_in_network_and_click_telemetry.kql](./kql/k2_ta419_domains_in_network_and_click_telemetry.kql) | Published domains in endpoint network events and Safe Links clicks |
| KQL | [k3_aitm_same_session_id_from_two_networks_officehome.kql](./kql/k3_aitm_same_session_id_from_two_networks_officehome.kql) | Same session ID used from a second IP and ASN after an OfficeHome MFA sign-in |
| KQL | [k4_public_figure_display_name_from_free_mail.kql](./kql/k4_public_figure_display_name_from_free_mail.kql) | Expert display names on inbound mail from free-mail providers |
| YARA | [ta419_bitb_phishing_page_and_lure.yar](./yara/ta419_bitb_phishing_page_and_lure.yar) | Two rules: saved phishing page or script with kit markers; exported email with campaign senders or lure text |
| Suricata | [ta419_ai_policy_phishing.rules](./suricata/ta419_ai_policy_phishing.rules) | Six sids: DNS for two domain groups, TLS SNI, certificate subject, `observe.js` request, the single VPS address |

None of these rules has been run against a real capture: Proofpoint published no sample, no hash of a page or script, and no network signature, so the kit strings come from its prose. The first email has no link, so the sender and the display name are the earliest signals; the domain rules fire only after the reply.

### Threat hunting hypotheses

- **H1** — reply-first impersonation of public experts from free-mail accounts: [peak_h1_reply_first_impersonation_of_policy_experts.md](./hunts/peak_h1_reply_first_impersonation_of_policy_experts.md).
- **H2** — shortened link, Turnstile, fake OneDrive page and BitB script paths: [peak_h2_fake_onedrive_redirect_chain_and_bitb_kit_paths.md](./hunts/peak_h2_fake_onedrive_redirect_chain_and_bitb_kit_paths.md).
- **H3** — Entra session replay after a relayed MFA sign-in: [peak_h3_entra_aitm_session_replay_after_mfa.md](./hunts/peak_h3_entra_aitm_session_replay_after_mfa.md).

## Incident response playbook

### First 60 minutes (triage)

1. Run H1 and the k1 query to list every recipient of a published sender or lookalike domain, and every high-value user who received a first-contact email from a free-mail account with an expert's display name.
2. For each recipient, check outbound mail for a reply and `UrlClickEvents` and proxy logs for a first-stage or second-stage domain. A reply without a click is still a risk: the link may arrive in the next message.
3. For anyone who clicked, run H3 on their sign-ins from the click time. Note the IP and ASN of the interactive sign-in and of every non-interactive sign-in on the same session ID.
4. Revoke sessions for every user who reached a second-stage domain, then reset the password and require a fresh sign-in from a managed device; do not wait for proof of replay.
5. Block the 19 domains in DNS and proxy and add the three sender addresses (not the free-mail domains) to the mail block list; keep the hits for the investigation.
6. Warn the impersonated people if they are in your circle, through a channel that is not the phishing thread, and tell recipients not to reply to or forward the messages.

### Artifacts to collect

| Artifact | Path | Tool | Why |
|---|---|---|---|
| Original emails | Defender "Download email" or Exchange message trace, `.eml` with full headers | Defender portal, `Get-MessageTraceV2` | First-hop Received line, sender, display name, link or no link |
| Entra sign-in logs | Interactive and non-interactive sign-in logs, 30 days | Sentinel, Graph `Get-MgAuditLogSignIn` | Session ID, IP, ASN, client app, MFA result |
| Unified audit log | Purview audit: `MailItemsAccessed`, `FileDownloaded`, `New-InboxRule`, `Consent to application` | `Search-UnifiedAuditLog` | What the second IP did with the session |
| Mailbox rules and forwarding | Exchange Online mailbox | `Get-InboxRule`, `Get-Mailbox` | Persistence through rules or forwarding |
| Registered MFA methods | Entra user authentication methods | `Get-MgUserAuthenticationMethod` | Methods added after the sign-in |
| OAuth grants | Entra enterprise applications and user grants | `Get-MgUserOauth2PermissionGrant` | Consent-based persistence |
| Browser history | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History` | `sqlite3`, Hindsight | Redirect chain from the shortened URL to the second-stage page |
| Proxy and DNS logs | Gateway and resolver logs | SIEM | Click time and every domain in the chain |

### IR queries and commands

```powershell
# Author: Jarmi
# End the sessions of a user who reached the relay page, then review what could keep access.
Connect-MgGraph -Scopes "User.ReadWrite.All","UserAuthenticationMethod.Read.All","Directory.Read.All"
$upn = "user@contoso.com"
Revoke-MgUserSignInSession -UserId $upn
Get-MgUserAuthenticationMethod -UserId $upn | Select-Object Id, AdditionalProperties
Get-MgUserOauth2PermissionGrant -UserId $upn | Select-Object ClientId, Scope, ConsentType
Get-InboxRule -Mailbox $upn | Select-Object Name, Enabled, ForwardTo, RedirectTo, DeleteMessage
```

```powershell
# Author: Jarmi
# Audit activity for the user in the window after the click (adjust the dates).
Search-UnifiedAuditLog -StartDate "2026-10-01" -EndDate "2026-10-15" -UserIds $upn `
  -Operations MailItemsAccessed,FileDownloaded,New-InboxRule,Set-InboxRule,"Consent to application" -ResultSize 5000 |
  Select-Object CreationDate, Operations, ClientIP, AuditData
```

```bash
# Author: Jarmi
# Domain list from the case feed, for a quick DNS or proxy log grep.
awk -F, '$1=="domain"{gsub(/\[\.\]/,".",$2); print $2}' iocs.csv | sort -u > /tmp/ta419_domains.txt
grep -F -f /tmp/ta419_domains.txt /var/log/dns/queries.log | head -50
```

### Containment, eradication, recovery

**Exit criteria:** every exposed user has had sessions revoked, the password reset and the authentication methods reviewed; no unexplained mailbox rule, forwarding address, OAuth grant or new MFA method remains; the audit log shows no mail or file access from a second network after the click; and the phishing domains and senders are blocked.

**Eradication.** Remove any rule, forward or grant that the user did not create. If the audit log shows mail or file access from the second network, scope what was read and notify the data owners; Proofpoint reports no such activity, so this is a check and not an expectation. Move the exposed users to a phishing-resistant method (passkeys or FIDO2 keys, as Proofpoint advises) and enforce it through conditional access; number matching, token protection and device-bound sessions are interim controls named by the CSA note.

**What NOT to do:**

- Do not reset the password and stop: the stolen session cookie stays valid until the sessions are revoked.
- Do not block `mail.com` or `outlook.com`; block the specific addresses. The domains are legitimate services.
- Do not reply to the impersonated expert on the same thread or from the same account to ask whether it is real; use a known channel.
- Do not open the second-stage page from a managed laptop; use an isolated browser with no signed-in profile.
- Do not treat a clean DNS check as clearing a user: the first click is on a URL shortener and the chain may use domains that are not on Proofpoint's list.

### Recovery validation

Re-run H1 to H3 daily for 30 days for the exposed group, confirm that no sign-in reuses a revoked session, and check that every high-value account now requires a phishing-resistant method. Review the conditional-access report for sign-ins from unmanaged devices on the OfficeHome client.

## IOCs

Proofpoint's indicator table has 23 entries; the full list, with the explicit kit paths, the certificate subject, the OfficeHome client ID, the lure strings and nine analyst notes, is in [iocs.csv](./iocs.csv) (42 rows). First-seen dates run from December 2025 to July 2026, so re-validate before treating any domain as live.

| Type | Value | Context | Confidence | Source |
|---|---|---|---|---|
| email | `leparker@mail[.]com` | Impersonates Lynne Edwards Parker; July 2026 | high | Proofpoint |
| email | `hcrediker@mail[.]com` | Impersonates Heidi Crebo-Rediker; July 2026 | high | Proofpoint |
| email | `hcrediker@outlook[.]com` | Impersonates Heidi Crebo-Rediker; July 2026 | high | Proofpoint |
| domain | `driftshare[.]co` | First-stage redirect; July 2026 | high | Proofpoint |
| domain | `globalfileshareplatform[.]com` | Second-stage AitM; July 2026 | high | Proofpoint |
| domain | `quickfly[.]online` | First-stage redirect; May 2026 | high | Proofpoint |
| domain | `smartsyncbox[.]com` | Second-stage AitM; May 2026 | high | Proofpoint |
| domain | `tw-koryu[.]org` | Sender domain spoofing Japan-Taiwan Exchange Association; May 2026 | high | Proofpoint |
| domain | `heritiages[.]org` | Sender domain spoofing The Heritage Foundation; March 2026 | high | Proofpoint |
| domain | `shinjirou[.]info` | Sender domain spoofing the Koizumi site; February 2026 | high | Proofpoint |
| ipv4 | `108.61.163[.]187` | VPS in a first-hop Received header; single observation | medium | Proofpoint |
| sha256 | `b314a1499cd728ca3e54b7150661fd0c7d2279065fe3f570f0f66c395d744460` | Hash of the shared self-signed TLS certificate (O=Castro Inc) | high | Proofpoint |
| string | `4765445b-32c6-49b0-83e6-1d93765276ca` | OfficeHome client ID driven by the kit; legitimate, a pivot only | high | Proofpoint |
| string | `/secondary/observe.js` | Telemetry and OTP automation module | medium | Proofpoint |
| string | `Request for Feedback on Military Integration of Claude` | February 2026 lure subject | high | Proofpoint |

No CVE is part of this campaign. The generated [kev.md](./kev.md) lists CVE-2026-76504 from the secondary finding below: it was added to CISA KEV on 2026-09-30 with a federal remediation due date of 2026-10-03, and ransomware use is listed as Unknown.

## Secondary findings

- **Cisco Catalyst SD-WAN Manager authentication bypass, CVE-2026-76504 (Help Net Security, 2026-10-01).** An HTTP request with improperly handled URI encoding bypasses an authentication rule on a specific API endpoint and gives access to the API as the admin user, regardless of system configuration; Cisco learned of exploitation in September 2026 through a TAC case. Releases 26.2, 26.1, 20.18, 20.15, 20.12, 20.9 and earlier are affected; fixes exist for 20.9 to 26.2, earlier systems should migrate, and no workaround exists. Cisco names `serviceproxy-access.log` and `vmanage-server.log` entries as indicators and warns they may appear in normal operation. The article does not say who exploits it.
- **UNK_SweetSpecter (IT Pro, 2026-10-02, citing Proofpoint).** A China-aligned cluster that Proofpoint reported earlier for AI-themed phishing of generative-AI organisations, including OpenAI employees, and that Proofpoint treats as distinct from TA419. It is useful as a reminder that AI companies and AI policy staff are both on the intelligence-collection list, not as evidence of a link between the two clusters.
- **Turnstile and no-link first contact defeat scanners (CSA research note, 2026-10-05; the note's own analysis).** The note argues that a link filter has nothing to evaluate in a message with no link, and that Cloudflare Turnstile may impede automated URL scanning and sandboxing. It is an inference from Proofpoint's description, but it explains why the sender and the Entra session are the better places to look.

## Pedagogical anchors

- **A link-free first email moves detection from content to identity.** When the first message has nothing to scan, the signals are who sent it, what name it carries and whether the recipient replied. Build the display-name and reply-pattern hunts before you need them.
- **MFA that a proxy can relay is not phishing resistance.** The sign-in is genuine because the proxy forwards it to Microsoft. Only origin-bound methods (passkeys, FIDO2) refuse to answer a page on the wrong domain.
- **The session ID is the thread to pull.** After the relayed sign-in, the interactive log and the non-interactive logs share a session ID; the same ID from a second IP and ASN is the evidence that matters whatever the lure or domain.
- **A fake browser window needs no iframe.** Frameless BitB builds the window in the page itself, so defences that look for an embedded frame miss it; the user-side habit is to check the address bar of the real browser, not the drawn one.
- **Indicators decay, and this list is nine months wide.** The domains date from December 2025 to July 2026. Use them to look back in logs, not as a live block list, and expect new ones.

## What's in this folder

| File | Purpose | Link |
|---|---|---|
| README.md | This case write-up. | [README.md](./README.md) |
| kill_chain.svg | Two-lane kill chain diagram (Template A). | [kill_chain.svg](./kill_chain.svg) |
| kev.md | CISA KEV cross-reference for this case's CVEs. | [kev.md](./kev.md) |
| iocs.csv | 42 rows: senders, domains, VPS address, certificate hash, kit paths, lure strings, notes. | [iocs.csv](./iocs.csv) |
| sigma/ | Four Sigma rules for DNS, proxy, kit paths and the certificate subject. | [sigma](./sigma/) |
| kql/ | Four queries for email, network and click telemetry, Entra session replay and display-name impersonation. | [kql](./kql/) |
| yara/ | Two YARA rules for saved phishing pages and exported lure emails. | [ta419_bitb_phishing_page_and_lure.yar](./yara/ta419_bitb_phishing_page_and_lure.yar) |
| suricata/ | Six Suricata sids for DNS, SNI, certificate subject, kit path and the VPS address. | [ta419_ai_policy_phishing.rules](./suricata/ta419_ai_policy_phishing.rules) |
| hunts/ | Three PEAK hunts H1 to H3. | [hunts](./hunts/) |

## Sources

- [Hallucinating Credibility: China-Aligned TA419 Impersonates Its Way into US AI Policy — Proofpoint, 2026-10-01](https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy)
- [China-Aligned TA419 Targets U.S. AI Policy Experts With Microsoft AitM Phishing — The Hacker News, 2026-10-04](https://thehackernews.com/2026/10/china-aligned-ta419-targets-us-ai.html)
- [Chinese hackers impersonate leading AI figures to harvest credentials — IT Pro, 2026-10-02](https://www.itpro.com/security/cyber-crime/chinese-hackers-impersonate-leading-ai-figures-to-harvest-credentials)
- [CyberScoop coverage of the Proofpoint TA419 report, 2026-10-01](https://cyberscoop.com/?p=90929)
- [TA419 Impersonates AI Policy Figures to Phish Experts — Cloud Security Alliance research note, 2026-10-05](https://labs.cloudsecurityalliance.org/research/csa-research-note-ta419-ai-policy-phishing-20261005-csa-styl/)
- [Frameless BitB — Wael Masri, GitHub](https://github.com/waelmas/frameless-bitb)
- [New Cisco SD-WAN zero-day exploited in-the-wild (CVE-2026-76504) — Help Net Security, 2026-10-01](https://www.helpnetsecurity.com/2026/10/01/new-cisco-sd-wAN-zero-day-exploited-in-the-wild-cve-2026-76504/)
