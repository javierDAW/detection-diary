# PEAK Hunt H1 — Fake-invitation phish kit URI signature across the estate

**Hypothesis.** If the fake event-invitation kit reached our users, then web/DNS/endpoint telemetry
contains the kit's **fixed request chain** (`/favicon.ico` -> `/blocked.html` -> `/Image/*.png`) and
POSTs to the backend endpoints (`/processmail.php`, `/process.php`, `/pass.php`, `/mlog.php`,
`/check_telegram_updates.php`), regardless of which `.de` domain was used.

**Why the URI chain.** The operator rotates ~80 domains, so domains are weak IOCs. The kit's
structure is fixed: the icon path, the fingerprint files and the PHP endpoints are constant across
the campaign and are therefore the durable hunt anchors.

## Prepare
- Identify web telemetry sources: proxy logs, `DeviceNetworkEvents`, Zeek `http.log`, DNS logs.
- Confirm 30-90 days of retention covers the campaign window (active since Dec 2025).
- Stage the kit URI list and the three seed domains.

## Execute
- Run `kql/phishkit_uri_signature_network.kql` over `DeviceNetworkEvents`.
- Run `kql/phishkit_lure_domain_contact.kql` for the seed domains.
- In proxy/Zeek, search URIs for: `/blocked.html`, `/Image/office360.png`, `/processmail.php`,
  `/process.php`, `/pass.php`, `/mlog.php`, `/check_telegram_updates.php`.
- Refresh the live domain list from the ANY.RUN TI query:
  `url:"/blocked.html" AND url:"/favicon.ico" AND url:"/Image/*.png"`.

## Analyze / pivot
- A request to `/processmail.php` or `/pass.php` from an internal host is a **credential-submission**
  event — treat the user as phished and pivot to H3 (account takeover).
- A `/check_telegram_updates.php` hit confirms the Google flow with Telegram exfil.
- Cross-reference the source user/host against `UrlClickEvents` to find the delivering email.
- Hosts that fetched the icon set but did **not** POST may have abandoned the lure — still worth a
  user awareness note.

## Document / hand off
- For each phished user, record the flow (credential/OTP vs RMM), the timestamp and the lure domain.
- Promote confirmed credential submissions to incident; feed RMM-download hosts into H2.
- Add any new domains discovered to the proxy blocklist and to `iocs.csv`.
