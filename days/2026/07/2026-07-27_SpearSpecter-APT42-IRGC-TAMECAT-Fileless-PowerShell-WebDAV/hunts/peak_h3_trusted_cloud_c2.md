# PEAK Hunt H3 — trusted-cloud C2 beacon and Sec-Host header (TAMECAT)

**Prepare**

- Hypothesis: If C2 is live, a single host beacons to Cloudflare Workers module subdomains under `darijo-bosanac-dl.workers.dev`, keeps a `*.firebaseio.com/OutlookStandaloneUpdate/<host-id>` heartbeat, and sends an AES IV in a custom `Sec-Host` HTTP header - all AES-256 encrypted.
- Scope: all egress; prioritise hosts flagged by H1/H2.
- Data: proxy logs with header capture, TLS SNI logs, Sysmon EID 3/22, Defender `DeviceNetworkEvents`.
- ATT&CK: T1071.001, T1102.002, T1573.001.

**Execute**

1. Find hosts contacting multiple random subdomains of `darijo-bosanac-dl.workers.dev`, or `line.completely.workers.dev`, initiated by `powershell/curl/conhost/msedge`.
2. Find `*.firebaseio.com` requests whose URI contains `OutlookStandaloneUpdate` (per-host beacon).
3. If header telemetry exists, alert on requests carrying a `Sec-Host` header to any of the above fronts.
4. Correlate to `zx3nkaavlai.map.azionedge.net` and `s3.tebi.io` (staging/exfil edges).

**Act**

- True positive: isolate, block the specific disposable hosts (not Cloudflare/Firebase/Telegram/Discord wholesale), rotate exposed credentials AND revoke sessions/tokens (stolen cookies survive password resets), pivot to full scope.
- Tuning: baseline legitimate Cloudflare Workers / Firebase use per org; the `Sec-Host` header and `OutlookStandaloneUpdate` path are the discriminators.

**Knowledge**

- Record live C2 subdomains with first/last-seen; they decay fast. Note whether Telegram/Discord are business-required (if not, candidates to block outright).
