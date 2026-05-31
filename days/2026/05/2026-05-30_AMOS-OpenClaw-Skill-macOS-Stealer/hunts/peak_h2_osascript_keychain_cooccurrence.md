# H2 — osascript fake-password dialog co-occurring with login.keychain-db access

## Frame

Prepare-Execute-Act-Know hunt. AMOS reaches credential collection by asking the
user for the password through a fake `osascript display dialog ... hidden
answer` prompt, then unlocking and reading the login Keychain directly
(glueckkanja confirmed `cat ~/Library/Keychains/login.keychain-db`). Each
signal is individually rare; together on one host inside a short window they
are ground-truth stealer collection.

## Hypothesis

If AMOS reached collection on a Mac in our fleet, we will observe an `osascript`
process running a `display dialog` with `hidden answer` and a password prompt,
followed within minutes by a `cat`/`cp`/`ditto`/`zip` process referencing
`Keychains/login.keychain-db`, on the same device.

## Expected benign baseline

`login.keychain-db` is normally touched only by `securityd` and Keychain Access
through the Security framework — never by `cat`/`cp`/`ditto` on its raw path.
A handful of admin/helper apps prompt for a password via AppleScript, but they
do not then copy the raw Keychain database.

## Action on match

Treat as confirmed credential theft: forensically copy the Keychain and any
`/tmp/*.zip`, enumerate browser profiles for stolen wallet extensions, begin
credential rotation and wallet-drain monitoring, and pivot to H3 for exfil
confirmation.

## Query — Defender XDR

```kql
let lookback = 14d;
let dialogs =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "osascript"
    | where ProcessCommandLine has "display dialog" and ProcessCommandLine has "hidden answer"
    | where ProcessCommandLine has_any ("password", "Password", "passcode")
    | project DialogTime = Timestamp, DeviceName, DialogCmd = ProcessCommandLine;
let keychain =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("cat", "cp", "ditto", "zip", "tar", "rsync")
    | where ProcessCommandLine has "Keychains/login.keychain-db"
    | project KeychainTime = Timestamp, DeviceName, KeychainCmd = ProcessCommandLine;
dialogs
| join kind=inner keychain on DeviceName
| where KeychainTime between (DialogTime .. (DialogTime + 30m))
| project DeviceName, DialogTime, DialogCmd, KeychainTime, KeychainCmd
| order by DialogTime asc
```

## Notes

If GUI-input telemetry is thin, run the two halves independently — a raw
`login.keychain-db` read by a copy/archive tool is high-fidelity even without
the matching dialog.
