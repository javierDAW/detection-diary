# PEAK Hunt H3 — NFC relay-transport egress from the mobile fleet

**Hypothesis.** A managed Android device egresses to one of the NFC relay transports: raw-TCP /
TLS to the DevilNFC C2 domains, MQTT (TCP 1883) to a non-corporate broker (NFCMultiPay v2), the
NFCMultiPay REST endpoints (`/api/nfc/*`), or the Telegram Bot API from a banking-categorised
app. Either confirms the live relay channel that carries the APDU stream and the harvested PIN.

**Why it works.** The relay needs a low-latency channel between the victim's reader and the
attacker's tapper. DevilNFC uses a persistent raw-TCP socket with Protobuf framing
(OP_SYN/ACK/PSH/FIN, `TCP_NODELAY`); NFCMultiPay started on HTTPS REST polling (`/api/nfc/poll`)
and moved to event-driven MQTT on 1883, publishing a *retained* `nfc/relay/<pin>/card_ready`
message carrying the PIN + last-4 PAN + brand. The transports rotate, but the *shapes* — MQTT
from a phone to a random broker, `/api/nfc/*` REST, Telegram exfil from a "bank" app — persist.

## Data sources
- `DeviceNetworkEvents` / MTD flow telemetry: remote IP/URL/port, initiating app.
- Egress firewall / NetFlow for TCP 1883 from the mobile subnet.
- DNS logs for the DevilNFC C2 domains and any newly-registered relay-looking domains.

## Analytic steps
1. Sweep mobile-fleet egress for TCP **1883** to any broker not on the corporate IoT/MQTT
   allow-list — MQTT from a phone is unusual and a strong lead even after the IPs change.
2. Match outbound to the known NFCMultiPay broker IPs (`185.203.116.18`, `47.253.167.219`) and
   the DevilNFC C2 domains (`nfcrackatm.com`, `spicynagets.shop`).
3. Hunt HTTP/S requests with URIs `/api/nfc/check-pin`, `/api/nfc/poll`, `/api/nfc/publish`, or
   `api_pin.php`.
4. Flag Telegram Bot API traffic (`api.telegram.org/bot...`) initiated by an app categorised as
   banking/finance — legitimate banking apps do not talk to Telegram bots.
5. Correlate any hit back to the device's installed-app inventory (H1) and the Kiosk/PIN/OTP
   behaviour (H2) to confirm.

## Expected benign
MQTT/1883 is legitimate for corporate IoT — allow-list those brokers. `api.telegram.org` is
widely used; only treat it as suspicious from a banking/finance app. C2 IP/domain IOCs rotate,
so absence does not clear the device — keep the behavioural hunts active.

## Pivots / escalation
Egress to a relay transport from a phone running a non-wallet HCE app (H1) with the Kiosk/PIN/OTP
chain (H2) → confirmed NFC relay infection: isolate, reissue the card, reset credentials through
a trusted channel, and submit the package hash + C2 to issuer fraud intel and threat feeds.

Linked detections: `suricata/nfc_relay_c2_and_transport.rules`,
`kql/devilnfc_c2_pin_exfil_network.kql`, `kql/nfcmultipay_mqtt_rest_relay.kql`.
