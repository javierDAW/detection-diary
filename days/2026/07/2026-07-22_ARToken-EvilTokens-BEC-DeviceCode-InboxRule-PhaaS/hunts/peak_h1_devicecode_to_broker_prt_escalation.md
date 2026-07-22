# PEAK Hunt H1: Device Code Sign-In to Broker/PRT Escalation

## Hypothesis (PEAK format)

**If** a standard user account completes an OAuth 2.0 device code sign-in, **then** a Microsoft
Authentication Broker (WAM) sign-in for the same user from a new device or IP address will follow
within a short window, as the operator escalates the captured token into a Primary Refresh Token
(PRT) -- a persistence mechanism documented in the ARToken/EvilTokens API surface
(`/prt/setup -> /prt/refresh -> /prt/renew -> /prt/reacquire -> /prt/cookie`) that explicitly
survives a victim password reset.

## Why this hunt matters

Device code phishing is now a commodity technique sold by multiple competing PhaaS platforms
(EvilTokens, ARToken, Kali365). The device-code completion itself is often the only visible event;
the PRT escalation that follows is the step that converts a one-time credential theft into durable,
remediation-resistant access. Catching the handoff between the two events is far higher value than
alerting on either event in isolation, both of which have legitimate use cases on their own.

## Data sources

- Microsoft Entra ID `SigninLogs` (`AuthenticationProtocol`, `AppDisplayName`, `IPAddress`,
  `DeviceDetail`, `ResultType`)
- Microsoft Graph sign-in and audit logs for device registration events

## Procedure

1. Query `SigninLogs` for all `AuthenticationProtocol == "deviceCode"` completions
   (`ResultType == 0`) in the lookback window, excluding known input-constrained-device
   applications (Azure CLI, kubectl, smart-TV/media apps).
2. For each surviving user/session, query `SigninLogs` for any `AppDisplayName == "Microsoft
   Authentication Broker"` completion for the same user within the following 6 hours.
3. Filter to cases where the broker sign-in IP/ASN differs from the device-code sign-in IP/ASN,
   or where the associated device ID has no prior registration history for that user.
4. Triage survivors: confirm with the user whether they knowingly authorized a device-code sign-in
   (e.g. for a legitimate CLI tool); if not, treat as a confirmed PRT-escalation compromise and
   proceed to the IR playbook's first-60-minutes checklist.

## Companion artifact

See `kql/artoken_devicecode_then_broker_prt_escalation.kql` for the runnable join query.

## Expected false positives

- Legitimate corporate-managed device provisioning shortly after a CLI login on the same
  device/network.
- Roaming users on VPN or mobile carrier IP ranges that legitimately change ASN between the two
  events; correlate with device compliance state before escalating.
