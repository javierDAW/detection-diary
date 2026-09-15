# PEAK hunt H3 - At-risk people: personal devices, messaging contact and account tokens

## Prepare

**Hypothesis.** The first contact in this campaign is a message on WhatsApp, Telegram or Instagram from someone the target knows,
or from "technical support", and the operator moves from a work device to a personal one when the first attempt fails. Evidence
therefore sits in the person's accounts and personal machine, not in the corporate SIEM. The FBI analysis also lists `MsCache.exe`,
which uses Selenium and a legitimate `chromedriver.exe` to collect Gmail OAuth tokens and send them to Telegram.

**Why.** For a newsroom, NGO, university or diaspora organisation, the defensible control is a short, voluntary check with the
person at risk, not a fleet query. The NCSC publishes free guidance and services for high-risk individuals.

**Scope.** Staff and associates who report on or oppose the Iranian state, and anyone who received an unsolicited installer or
a "scan result" file over a messaging app since 2025. This hunt is a guided conversation plus account-side checks.

**Data quality check first.** Agree consent and a safe channel before you ask anyone to run anything on a personal device. Do not
use the possibly compromised messaging channel to coordinate.

## Execute

```text
Checklist for the conversation (no tooling needed):
1. Did anyone you know ask you to install or open a file in WhatsApp, Telegram or Instagram (video tools, antivirus, a Telegram "authenticator", a password manager, a scan result)?
2. Did the contact push you to a different device or ask you to try again on a personal computer?
3. List recent sign-ins and devices for email and messaging accounts; look for unknown devices and unexpected third-party access.
```

```cmd
:: Author: Jarmi
:: With the person present on the personal Windows machine: persistence and exclusions first.
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
dir /a "C:\Windows \"
powershell -NoProfile -Command "(Get-MpPreference).ExclusionPath"
```

```kql
// Defender XDR, managed devices only: collection tooling dropped beside the implants, and the hash list from iocs.csv.
// Run k3_chosen_brick_known_samples_and_collection_tooling.kql.
```

## Act

**A positive finding on a person's device** is also a safety matter: tell them first, in person or on a trusted channel, before
changing anything on the device, and involve the national authority named in the advisory (UK NCSC, FBI IC3, AIVD or local police).
Rotate account credentials and revoke third-party access from a clean device, not from the infected one.

**Suspected token theft** means revoking sessions and third-party access for the mail account and re-checking forwarding rules and
sign-in history after the clean-up.

**No findings** do not clear the person: tell them what was and was not checked, and keep the sign-in review on a schedule.
