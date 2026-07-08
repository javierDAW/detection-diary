# PEAK Hunt H3 - Montana Empire kit artifacts across the estate

**Hypothesis:** A user, developer or agent in our environment fetched or landed on the Montana Empire phishing kit (or the malicious postal APK), leaving the kit's hashes, URI paths or branding strings in host, proxy or file telemetry.

**PEAK type:** IOC-driven, reactive.

## Prepare
- Load the two SHA256 hashes, the kit URI paths (`/mentalite.php`, `/panel_track.php`, `/verify_api.php`, `/letgovip.zip`) and the branding strings (`ENTER THE EMPIRE`, `Enter Access Key`, `Kimseye Guvenme`).
- Stage the YARA file `phantom_squatting.yar` for file-share and endpoint scans.

## Execute
- Hash sweep: `DeviceFileEvents | where SHA256 in (<hashes>)` (KQL `phantom_kit_hash.kql`).
- URI sweep: `DeviceNetworkEvents`/proxy for the kit paths (KQL `phantom_kit_uri_access.kql`, Sigma `phantom_kit_uri_proxy.yml`, Suricata sid:20260801-20260804).
- Download sweep: LOLBin/utility command lines referencing the artifact names (Sigma `phantom_kit_artifact_download.yml`).
- File-content sweep: YARA over web roots, download folders and mail attachments.

## Analyze
- A hash or URI hit is high fidelity - move straight to victim triage (what did they submit? card, IBAN, national ID, OTP?).
- For a landing without submission, still assume the domain is a live phantom and block it; check whether an AI agent (H2) routed the user there.
- Telegram exfil (Suricata sid:20260805) near a hit corroborates active credential relay.

## Knowledge
- Feed confirmed domains back to H1's watchlist and to the org blocklist.
- Because the kit repacks and rebrands per campaign, weight the URI/string/behaviour hunts above the static hash for durability.
