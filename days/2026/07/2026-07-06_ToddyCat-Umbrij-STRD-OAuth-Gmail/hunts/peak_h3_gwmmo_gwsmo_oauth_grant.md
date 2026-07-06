# PEAK Hunt H3 - Unexpected OAuth grant to GWMMO/GWSMO and Gmail API reads

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1528 Steal Application Access Token; T1114.002 Email Collection: Remote Email Collection.

## Hypothesis
An OAuth token has been minted for the Google Workspace Migration for Microsoft Outlook (GWMMO,
client_id `279448736670`) or the Google Workspace Sync for Microsoft Outlook (GWSMO, client_id
`1095133494869`) app in an environment that is not actively migrating from Outlook. Umbrij abuses
these two legitimate Google client IDs so its OAuth request blends in; the token then reaches Gmail
(scope `https://mail.google.com/`), Contacts, Calendar and Drive via the Google API.

## Prepare - data sources
- Google Workspace Admin audit logs (OAuth token / API access), ideally via Defender for Cloud Apps
  `CloudAppEvents`.
- Google account `Security > Third-party apps with account access` (per-user grants).
- The endpoint side (H1): the browser that produced the authorization code and the local log file
  holding it.

## Execute - logic
1. Enumerate token grants and API access tied to client_id `279448736670` or `1095133494869`, or to
   app names "...Migration for Microsoft Outlook" / "...Sync for Microsoft Outlook" -
   `kql/umbrij_gwmmo_gwsmo_oauth_grant.kql`.
2. Correlate each grant with a corresponding H1 headless-browser launch on one of the user's hosts in
   the same window.
3. Distinguish the Umbrij request shape from the legitimate app: Umbrij's request carries
   `flowName=GeneralOAuthFlow` and omits PKCE (`code_challenge`), `state` and `login_hint`, and uses
   `redirect_uri=http://localhost` (legit uses `http://localhost:61619/callback`).
4. Review Gmail/Drive/Contacts API read volume following the grant for bulk correspondence pulls.

## Act - triage
- **Confirmed:** a GWMMO/GWSMO grant with no matching migration project, correlated with an H1 launch,
  followed by Gmail API reads. Revoke the grant immediately (this invalidates the token), then rotate
  and force re-auth.
- **Escalation:** multiple users' accounts show the same app grant from the same set of hosts.
- **Benign:** an in-flight, ticketed Outlook-to-Workspace migration; confirm with the messaging team
  and the change record.

## Knowledge - notes
Revoking the OAuth grant at `myaccount.google.com/connections` invalidates every token issued to that
app - it is the fastest containment for token theft, faster than a password reset (which does not kill
an existing OAuth token). Maintain an allowlist of expected third-party Google apps so a new grant to a
migration tool is an alert, not noise.
