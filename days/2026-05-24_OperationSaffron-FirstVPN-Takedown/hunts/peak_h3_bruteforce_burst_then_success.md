# PEAK H3 — Failed-then-success burst from First VPN exit IP as affiliate dwell-time anchor

## Hypothesis
At least one corporate identity-provider, VPN gateway, RDP gateway, or public SSH bastion saw a burst of failed authentication attempts (≥5 failures) followed by a success from the same First VPN exit IP within a 24-hour window. This is the canonical password-spray-then-pivot pattern that the FBI FLASH explicitly attributes to First VPN use by ransomware affiliates and IABs. The success event is the dwell-time anchor for the downstream ransomware engagement.

## Why this discriminates
A failed-burst-then-success is a strong adversary-action signature even without IP enrichment. Combining it with the FBI IP list raises confidence to the highest available pre-incident anchor — the kind of signal that would have justified per-account session termination if it had been visible at the time. Today, six months after the activity window, this hunt produces the missing dwell-time data for the SOC's after-action review of any 2024-2026 ransomware engagement.

## Expected benign vs malicious
- Benign: a legitimate user who forgot their password, mistyped it five times, then succeeded — possible but rare, especially from an exit-node country that does not match the user's typical geo. Discriminate using `DeviceDetail.browser`, `DeviceDetail.operatingSystem`, and `ClientAppUsed` — the burst-then-success from a Linux user-agent on a typically-Windows account is malicious. Also discriminate by app: a burst-then-success against `Microsoft.Office.SharePoint`, `Office365 Shell WCSS-Client`, or a custom service-principal — particularly worth a closer look.
- Malicious: any burst against an Entra ID app that the user does not normally use, followed by a success that subsequently triggers the user's first-ever consent grant, mailbox rule, or new OAuth scope acquisition.

## Data sources
- Microsoft Entra ID — `SigninLogs`.
- Okta System Log — `eventType eq "user.session.access_token"`, `eventType eq "user.authentication.sso"`.
- Duo Auth API — `event_type=authentication`, `result=success`/`failure`.
- VPN gateway syslog.
- SSH bastion `auth.log`.

## Search logic
See [`../kql/firstvpn_failed_then_success_burst.kql`](../kql/firstvpn_failed_then_success_burst.kql). The same `join` pattern applies to Okta and bastion logs — read failures into a left, successes into a right, join on `(account, src_ip)`, filter the `success_time` window relative to `first_failure`.

## Time window
Two years (730 days) retroactive.

## Action on match
1. Open a triage ticket per `(UserPrincipalName, IPAddress, success_time)` tuple.
2. Pull the user's session history for the 30 days following the success — look for privilege escalation, mailbox rule changes, new OAuth grants, sudden onboarding of a new device, or first-time access to a sensitive resource.
3. Compare against the open ransomware IR tickets of the same period — if any IR engagement occurred for the user's organizational unit within 90 days of the success, treat this as the affiliate's dwell-time anchor and update the IR after-action report accordingly.
4. If the user is privileged or tier-0, force password reset + MFA re-registration + revoke all refresh tokens; rotate any service-principal secrets owned by the user. See Day 23 Storm-2949 SSPR playbook for the full identity-recovery sequence.

## Notes
- The window choice (24 hours between first failure and success) is conservative — affiliates often take longer for low-and-slow password sprays. Run the query at 24h, 48h, and 7d window sizes to compare confidence.
- Pair with PEAK H1 (any successful auth from First VPN IP) as the wider net, and use H3 to rank by confidence.
- High-confidence H3 matches are also the **best candidates to share with national law enforcement** under the Europol 506-user notification framework — if your organization is a victim and a user is implicated as either insider or compromised account, the JIT may already have associated user-database evidence.
