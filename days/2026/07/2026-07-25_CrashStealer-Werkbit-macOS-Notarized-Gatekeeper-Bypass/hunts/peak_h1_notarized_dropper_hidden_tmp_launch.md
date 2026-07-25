# H1 -- Application launched from a hidden /tmp dot-directory on macOS

## Frame

Prepare-Execute-Act-Know hunt. CrashStealer's second-stage payload is copied into a hidden
directory at /private/tmp/.CrashReporter, stripped of its original signature, re-signed ad
hoc, and launched from that hidden path. Any fleet with macOS process telemetry (Jamf
Protect, Microsoft Defender for Endpoint, CrowdStrike Falcon for Mac, or raw Endpoint
Security Framework events) can hunt this without extra instrumentation.

## Hypothesis

If a CrashStealer-class payload executed on a Mac in our fleet, we will observe an
application bundle's executable launched from a path matching a hidden dot-directory under
/private/tmp or /tmp, i.e. `/private/tmp/.<name>/<App>.app/Contents/MacOS/<exec>`.

## Expected benign baseline

Near zero. Legitimate macOS software installs into /Applications, a user's home directory,
or a package manager's managed path -- not a hidden folder under the world-writable temp
directory. The rare exception is developer/CI tooling that deliberately stages a bundle
under a self-created hidden /tmp path for automated testing; these are typically tied to a
known build-agent parent process and a predictable, recurring naming pattern.

## Action on match

Capture the full process tree and the parent (installer, curl/bash downloader, or another
staged binary), hash the executable and compare against any published CrashStealer
indicators, check for a corresponding disk image mount event
(`hdiutil attach -nobrowse -noverify`) shortly before the launch, and pivot to H2 (dscl
-authonly + Keychain unlock) and H3 (staged archive + libcurl exfil) to confirm the full
chain before declaring a false positive.
