# H2 -- dscl -authonly and login Keychain unlock co-occurrence

## Frame

Prepare-Execute-Act-Know hunt. CrashStealer shows a fake native password prompt, validates
whatever the victim enters via `dscl . -authonly <user> <password>`, caches it locally, then
immediately reuses it to unlock the login Keychain through Apple's `security` command-line
tool. Neither signal alone is unique to malware -- Apple's own authentication flow also uses
`dscl -authonly` -- but the two co-occurring within minutes, initiated by a non-Apple parent,
is high-confidence credential theft.

## Hypothesis

If CrashStealer-class credential theft occurred on a host, we will observe a `dscl -authonly`
call from a non-Apple-system parent process, followed within a short window by a login
Keychain unlock/access event on the same host and user session.

## Expected benign baseline

A few legitimate admin or IT-management tools validate a local password via `dscl` for
account-management purposes, and Keychain unlocks happen constantly as part of normal user
activity (browser autofill, password-manager unlock, app authentication). The narrow
co-occurrence -- a non-Apple `dscl -authonly` call immediately followed by a Keychain access
from the same process lineage -- is far rarer and near-zero noise in most fleets.

## Action on match

Identify the parent process that called `dscl`, resolve its on-disk path and code-signing
status (an ad hoc or missing signature strengthens the finding), check for a subsequent
LaunchAgent write matching the CrashStealer persistence pattern (H1's sibling detection),
and treat the account's password, browser credentials, and any crypto wallets on the host as
compromised pending full triage -- do not wait for confirmed exfiltration before starting
containment.
