# PEAK hunt H3 -- macOS credential collection and HTTP POST exfil

**Hypothesis.** If AMOS/MacSync ran, a non-Apple process accessed the login Keychain and browser stores, staged an archive, and exfiltrated over HTTP POST.

**Prepare.** Scope to macOS endpoints with process and network telemetry. Look back 14 days.

**Execute.**
- Non-Apple process reading or copying `login.keychain-db`, `~/Library/Keychains/`, a browser `Login Data`/`Cookies` store, SSH keys, or wallet directories.
- `osascript` presenting a password dialog (`display dialog ... with hidden answer`) or `security find-generic-password` / `dump-keychain`.
- Archive creation (`zip`/`ditto`/`tar`) of those artifacts followed by an outbound HTTP POST to a low-reputation host.

**Analyze.** Chain the credential-access event to the H2 `curl`-to-shell precursor on the same host and to the exfil POST. Together they confirm the full ClickFix-to-AMOS chain.

**Know.** Rotate every credential the stealer could reach from a clean device, revoke sessions/cookies, and add the collection endpoint to blocking.

Related: `../sigma/03_macos_infostealer_keychain_copy.yml`, `../kql/k3_macos_osascript_password_and_keychain.kql`.
