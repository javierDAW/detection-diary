# PEAK hunt H1 - Process lineage: app bundle clears quarantine, a shell runs from stdin, a hidden Mach-O appears in /tmp

## Prepare

**Hypothesis.** If a MacSync loader ran on a Mac, then an application bundle (often launched from a mounted disk image) ran `xattr -cr`
on itself, a shell ran a script it read from standard input (`zsh -s`), and a hidden file named `/tmp/.sys-<16 characters>` was written
and executed within the same few minutes. Kaspersky documents each step; the chain is the signal because every single step has a
benign explanation.

**Why first.** The first four stages are the only ones that exist before the operator ships any payload-specific tooling, and the
loader, downloader and dropper are the part that changes least between builds (six loader hashes and six stage 3 hashes were published).

**Scope.** macOS endpoint process and file telemetry for the last 30 days, with priority on developers and staff who handle
cryptocurrency. Securelist states that the family "primarily targets developers, crypto enthusiasts" and related IT and crypto users.

**Data quality check first.** Confirm that your macOS sensor records the parent process path and the full command line of `xattr`
and `zsh`. If it records neither, run H2 instead; it relies on disk state, not process history.

## Execute

```kql
// Defender XDR: xattr -cr launched by a process inside an app bundle, followed by a hidden .sys- file on the same device.
let clears = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName == "xattr" and ProcessCommandLine has "-cr"
    | where InitiatingProcessFolderPath has ".app/Contents/MacOS/" or InitiatingProcessFolderPath has "/Volumes/"
    | project DeviceId, DeviceName, ClearTime = Timestamp, Loader = InitiatingProcessFolderPath, LoaderSHA256 = InitiatingProcessSHA256;
let staging = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any ("/tmp/", "/private/tmp/") and FileName matches regex @"^\.sys-[0-9A-Za-z]{16}$"
    | project DeviceId, StageTime = Timestamp, StagedPath = FolderPath;
clears
| join kind=inner staging on DeviceId
| where StageTime between (ClearTime .. ClearTime + 30m)
| project DeviceName, ClearTime, StageTime, Loader, LoaderSHA256, StagedPath
```

```bash
# Author: Jarmi
# Live host: hidden staging files and shells that are reading a script from standard input.
ls -la /tmp /private/tmp 2>/dev/null | grep -E '\.sys-[0-9A-Za-z]{16}$|osalogging\.zip'
ps -axo pid,ppid,user,lstart,command | grep -E 'zsh -s|/bin/sh -s' | grep -v grep
```

## Act

**A match on both steps** is a priority finding: isolate the Mac but keep it powered, collect the loader bundle, `/tmp/.sys-*`, the
shell history and the unified log for the window, and treat every credential stored on the host as exposed (Keychain, browser
sessions, SSH keys, AWS, Kubernetes and git credentials are all on the collected-data list). Go to H2 on the same host.

**`xattr -cr` without a staging file** is a weaker lead; check the bundle's code signature and where it came from before closing.
Securelist notes that later stages are ad-hoc signed, so a validly signed bundle does not clear the host.

**No hits** do not clear a host on an old sensor build or one without parent-path telemetry; say so in the report.
