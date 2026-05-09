# PEAK H1 — Sideload + AccessibilityService grant within 24h on a banking-app device

## Hypothesis

On the corporate-mobile fleet, a device that within 24 hours installed a package from a non-store, non-system source **and** then enabled an AccessibilityService for that same package, while at least one banking, fintech or cryptocurrency wallet app is also installed, is a high-confidence Albiriox-class precursor.

## Why this discriminates

- Legitimate sideload on a managed corporate fleet is rare and is almost always done by the MDM (`InstallerPackageName` equals the MDM's package). Filtering on Installer = MDM kills the largest false positive group.
- Legitimate apps that bind an AccessibilityService are usually pre-installed (`com.android.*`, `com.google.*`, `com.samsung.*`) or specific user-chosen accessibility tools (TalkBack, switch access). Apps installed less than 24 hours ago that immediately demand AccessibilityService are extremely suspicious.
- The presence of a banking, fintech or wallet package raises the value of the precursor: it is the population Albiriox actually targets via its hardcoded `AppInfos` list of more than 400 financial apps.

## Expected benign vs malicious

- **Benign:** Intune sideload of a new line-of-business kiosk app that uses AccessibilityService to drive a custom UI; the user has a banking app on the same device. Filter by `Installer == <MDM package>`.
- **Malicious:** sideload from a file manager / browser / unknown installer; AccessibilityService granted within minutes; the user has a banking or wallet app present.

## Action on match

1. Quarantine the device in MDM (Intune Lost mode / Workspace ONE block / Lookout containment).
2. Capture an `adb bugreport` if the device permits it; otherwise, capture MDM-side telemetry exports.
3. List `enabled_accessibility_services`, `enabled_notification_listeners` and `sms_default_application` via MDM agent or `adb shell`.
4. If the user reports recent banking activity, contact the bank to freeze the app session and review last 30 days of transactions.
5. **Move on-chain crypto balances to a clean wallet before any factory reset** if a wallet app is involved.
6. Factory reset, re-enrol with fresh provisioning, rotate every TOTP and credential that may have been keylogged or read from notifications.

## KQL — Defender XDR Mobile (illustrative)

See [`../kql/albiriox_sideload_accessibility_with_banking_app.kql`](../kql/albiriox_sideload_accessibility_with_banking_app.kql).

## SPL — Splunk MTD CIM

See [`../spl/albiriox_mtd_correlation.spl`](../spl/albiriox_mtd_correlation.spl).

## References

- Cleafy Labs — Albiriox Exposed: A New RAT Mobile Malware Targeting Global Finance and Crypto Wallets — https://www.cleafy.com/cleafy-labs/albiriox-rat-mobile-malware-targeting-global-finance-and-crypto-wallets
- Android Developers — Secure sensitive activities — https://developer.android.com/security/fraud-prevention/activities
