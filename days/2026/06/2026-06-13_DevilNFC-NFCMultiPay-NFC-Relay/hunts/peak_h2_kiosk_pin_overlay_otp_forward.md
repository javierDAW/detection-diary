# PEAK Hunt H2 — Kiosk lock + PIN overlay + OTP forwarding on one device

**Hypothesis.** A single managed Android device shows the DevilNFC trap-and-harvest behavioural
chain within a short window: a non-MDM app starts Kiosk Mode / lockTask (screen pinning, system
UI hidden, back button neutralised), renders an overlay or WebView prompt asking for the card
PIN, and reads/forwards inbound SMS (OTP) — all while an NFC read takes place.

**Why it works.** DevilNFC's `KioskActivity` locks the victim inside a C2-served fake banking
interface with no exit while the relay completes; a remote-template pop-up then harvests the
4-digit PIN (and a second form the e-banking password), and `SmsPermissionManager` polls inbound
SMS to forward bank OTPs in real time. Each step alone has benign analogues, but the *sequence*
on one device in minutes is high-signal. The PIN capture is the force-multiplier — it lifts the
fraud past contactless limits to ATM and chip-and-PIN.

## Data sources
- MTD `mobile_event` telemetry: lockTask/Kiosk start, overlay/`SYSTEM_ALERT_WINDOW`, WebView
  credential prompt, SMS read / default-SMS change, NFC read events.
- MDM package allow-list (to identify the legitimate kiosk/MDM agents to exclude).
- User-reported "my bank app made me re-enter my PIN to verify".

## Analytic steps
1. Find devices where a non-MDM, sideloaded package entered lockTask/Kiosk or pinned the screen.
2. On those devices, look for an overlay/WebView credential or PIN prompt by the same package
   within the same session.
3. Add the SMS leg: SMS read or default-SMS-handler change by the same package, or OTP-shaped
   SMS access shortly after install.
4. Correlate with an NFC read event and any outbound connection to a relay transport (pivot to
   H3). The full chain (lock → PIN prompt → OTP read → NFC read → egress) is a confirmed-fraud
   pattern.
5. If recoverable, decode the APK and confirm `KioskActivity`, `api_pin.php`, and the SMS
   handler class.

## Expected benign
Approved single-purpose kiosk launchers (signage, POS lockdown) render in-app prompts —
allow-list them. MDM-driven lockTask is expected and excluded by the MDM filter. A legitimate
bank app never asks the user to re-enter the *card* PIN to "verify".

## Pivots / escalation
The full chain on one device → active card-present fraud in progress: stop the user from
completing the "verification" (it triggers the relay + PIN capture), isolate the device, force
credential reset through a trusted channel (not the phone), and notify the issuer to freeze and
reissue the card.

Linked detections: `sigma/android_kiosk_locktask_pin_overlay.yml`,
`sigma/android_sms_otp_forward_sideloaded_pkg.yml`.
