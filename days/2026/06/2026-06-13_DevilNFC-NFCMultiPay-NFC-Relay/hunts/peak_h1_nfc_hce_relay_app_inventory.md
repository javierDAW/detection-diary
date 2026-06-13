# PEAK Hunt H1 — Card emulation by a non-wallet, sideloaded Android app

**Hypothesis.** A managed Android device runs a sideloaded app that registers a
`HostApduService` (declares `android.nfc.cardemulation.host_apdu_service`) and/or holds
`android.permission.NFC`, despite not being a recognised wallet, bank, loyalty, or transit
app. This is the reader/tapper component of an NFC relay family (DevilNFC `com.devilnfc.reader`,
NFCMultiPay, NGate, SuperCard X), often installed shortly before or during a bank-themed
smishing wave.

**Why it works.** NFC relay requires an app that can read ISO-DEP cards (reader role) or
emulate a card via HCE (tapper role). Card emulation by an app outside the small set of
legitimate wallet/bank/transit apps is anomalous. DevilNFC further hides intent by declaring
only a single dummy AID (`F0010203040506`) and rerouting real payment AIDs with an Xposed hook
on `findSelectAid()`, so the declared AID list is not a reliable signal — registration of an
HCE service by a non-wallet sideloaded package is.

## Data sources
- MTD / Defender for Endpoint mobile inventory: installed packages, installer source, granted
  permissions (`NFC`, `BIND_NFC_SERVICE`, HCE service registration).
- `DeviceTvmSoftwareInventory` (package names), `DeviceEvents` (permission/HCE events).
- MDM app catalogue (to derive the approved wallet/bank/transit allow-list).

## Analytic steps
1. Enumerate every managed device with an installed package that registers a `HostApduService`
   or holds `android.permission.NFC`.
2. Subtract the approved wallet/bank/transit/loyalty allow-list and all store/system-installed
   packages (`com.android.vending`, OEM stores, `com.android.*`, `com.google.*`).
3. For each remaining package, pull the installer source — a sideloaded source (unknown,
   filemanager, browser, package_installer, or null) is the lead.
4. Cross-reference the install timestamp against any recent bank-themed smishing/WhatsApp lure
   reports for the same user/region.
5. Where the APK is recoverable, decode it (`apktool d`) and check the manifest for the HCE
   service, `findSelectAid` references, `libnfcgate.so`, the dummy AID, or the NFCMultiPay
   `/api/nfc/*` / `nfc/relay/` strings (Sigma + YARA in this folder).

## Expected benign
Legitimate sideloaded wallet, bank, loyalty, or transit apps use HCE; baseline and allow-list
the small approved set. Developer/test builds via adb on developer devices are rare on a
corporate fleet.

## Pivots / escalation
An HCE service registered by a sideloaded, non-wallet app → likely NFC relay malware: pivot to
H2 (Kiosk/PIN/OTP behaviour) and H3 (relay-transport egress), isolate the device in MDM, and
notify the issuer to watch the card for contactless/ATM authorisations from implausible
terminal geographies.

Linked detections: `sigma/android_nfc_hce_service_sideloaded_pkg.yml`,
`kql/devilnfc_nfcmultipay_app_inventory.kql`, `yara/devilnfc_nfcmultipay_nfc_relay.yar`.
