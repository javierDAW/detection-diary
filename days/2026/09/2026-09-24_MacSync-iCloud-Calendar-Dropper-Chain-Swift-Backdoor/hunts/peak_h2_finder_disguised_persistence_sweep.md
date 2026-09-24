# PEAK hunt H2 - Persistence sweep: Finder-disguised LaunchAgent, Application Support/System, .zshrc and global git hooks

## Prepare

**Hypothesis.** If the MacSync backdoor is installed, then the user profile holds a LaunchAgent labelled `com.apple.finder.agent`, a
directory `~/Library/Application Support/System`, a hidden `.repair-run` script and a hidden `~/Library/Logs/.sysnotif-agent.log`, and
the persistence command also appears in `~/.zshrc` and in the global git `pre-commit` and `post-checkout` hooks. Kaspersky documents
all of these; the multiple persistence points exist so that removing one is not enough.

**Why second.** The backdoor is the part that survives after the loader chain is gone, and it restores itself from the backup script.
A sweep finds it on hosts that were never monitored when the loader ran.

**Scope.** Every macOS device with a developer or crypto-handling user; run through your MDM or management agent as a read-only script.

**Data quality check first.** The sweep needs to read each user's home directory. Run it as root and loop over `/Users/*`; a run as the
console user alone misses other accounts.

## Execute

```bash
# Author: Jarmi
# Read-only sweep, run as root.
for H in /Users/*; do
  [ -d "$H" ] || continue
  echo "== $H"
  ls -la "$H/Library/LaunchAgents" 2>/dev/null | grep -i 'com\.apple\.' | grep -i finder
  ls -la "$H/Library/Application Support/System" 2>/dev/null
  ls -la "$H/Library/Logs/.sysnotif-agent.log" 2>/dev/null
  find "$H" -maxdepth 6 -name '.repair-run' 2>/dev/null
  grep -nE 'curl|osascript|base64|/tmp/|Application Support/System' "$H/.zshrc" 2>/dev/null
done
# Global git hooks are normally configured through core.hooksPath; check it and the default template directory.
git config --global --get core.hooksPath
git config --global --get init.templateDir
```

```kql
// Defender XDR: LaunchAgent plists with a com.apple.* label created in a user profile.
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has "/Library/LaunchAgents/" and FolderPath startswith "/Users/" and FileName startswith "com.apple."
| summarize First = min(Timestamp), Writers = make_set(InitiatingProcessFileName, 5) by DeviceName, FolderPath
```

## Act

**A `com.apple.finder.agent` plist in a user profile** is a high-quality indicator for this family: Apple ships its own launch items
under `/System/Library`, not in user LaunchAgents folders. Verify the program path with `plutil -p` and `codesign -dv --verbose=2`, then collect the
binary, the `.repair-run` script and the plist before removal.

**Eradication order matters.** Kaspersky describes `.repair-run` as a backup and restore script, so remove it and the `.zshrc` line and
the git hook content before unloading the LaunchAgent; otherwise a surviving copy may reinstall the backdoor. Reboot into a clean state and re-sweep, then rotate every credential that
the host held.

**No hits** do not clear a host where the backdoor was never installed because the chain stopped earlier; check H1.
