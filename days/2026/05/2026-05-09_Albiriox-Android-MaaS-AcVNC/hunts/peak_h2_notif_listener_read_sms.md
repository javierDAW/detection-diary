# PEAK H2 — Notification Listener + READ_SMS coexistence on a non-stock package

## Hypothesis

A non-stock, non-system Android package that holds **both** an active Notification Listener Service binding **and** the `READ_SMS` runtime permission is highly likely to be an OTP-stealing banking RAT. Albiriox, Anatsa, Brokewell and BingoMod all coincide on this footprint because they need to read OTP messages whether they arrive as SMS, as a push notification, or as both.

## Why this discriminates

- Stock SMS apps (Google Messages, Samsung Messages) do hold both, but they are pre-installed and signed by the platform vendor. Filter them out by package name.
- Most legitimate non-system apps that read SMS do not also bind the Notification Listener. The intersection is narrow.
- Unlike "AccessibilityService bind" hunts, this one survives fully against malware that disguises its accessibility service name; it is the **capability footprint** that matters.

## Expected benign vs malicious

- **Benign:** corporate-issued SMS handler that also displays push from the same workflow (rare); a legitimate two-factor authenticator that asks for `READ_SMS` to auto-fill OTP into its own UI.
- **Malicious:** any sideloaded app holding both, especially within 24 hours of an `AccessibilityServiceEnabled` event for the same package.

## Action on match

1. List the package name; cross-reference with the MDM application inventory.
2. If the package is unknown, treat as Albiriox-class precursor — execute the H1 action plan.
3. If the package is a known (but not allowlisted) third-party SMS app, decide policy: either allowlist the package or block it via MDM.
4. Maintain the allowlist. The corporate SMS handler, if any, should be the only third-party package allowed on this footprint.

## KQL — Defender XDR Mobile

See [`../kql/albiriox_notif_listener_with_read_sms.kql`](../kql/albiriox_notif_listener_with_read_sms.kql).

## References

- Cleafy Labs — Albiriox Exposed — https://www.cleafy.com/cleafy-labs/albiriox-rat-mobile-malware-targeting-global-finance-and-crypto-wallets
- The Hacker News — New Albiriox MaaS Malware Targets 400+ Apps — https://thehackernews.com/2025/12/new-albiriox-maas-malware-targets-400.html
