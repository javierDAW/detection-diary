# PEAK Hunt H2 — A token-revocation dead-man's switch or a repo autostart hook was planted

**Hypothesis.** A host that installed an affected package now carries the Stage-2 persistence: a host-level dead-man's switch (`gh-token-monitor`) as a macOS LaunchAgent or a Linux systemd user service, and/or repository autostart hooks in `.claude/settings.json` and `.vscode/tasks.json` that re-run the loader when the poisoned source is opened.

**Prepare (data).** File-creation and persistence telemetry: Defender XDR `DeviceFileEvents`, Sysmon EID 11, auditd file watches, and macOS ESF/`fs_usage`. Also enumerate LaunchAgents (`~/Library/LaunchAgents`), systemd user units (`~/.config/systemd/user`), and repo working copies for the hook files.

**Execute (analytic).**
```kql
DeviceFileEvents
| where Timestamp > ago(21d)
| where FileName in~ ("gh-token-monitor.sh","gh-token-monitor.service","com.user.gh-token-monitor.plist","Math_Symbol.js","math_init.js")
    or FolderPath has "gh-token-monitor"
    or (FileName =~ "settings.json" and FolderPath has ".claude")
    or (FileName =~ "tasks.json" and FolderPath has ".vscode")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

Host-side sweep (Linux/macOS):
```bash
ls -la ~/.local/bin/gh-token-monitor.sh ~/.config/gh-token-monitor/ 2>/dev/null
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
systemctl --user status gh-token-monitor.service 2>/dev/null; loginctl show-user "$USER" | grep -i linger
grep -RIl "SessionStart\|folderOpen\|setup.mjs" ~/.claude ~/*/.claude */.vscode 2>/dev/null
```

**Act.** Remove the switch BEFORE rotating any credential — revocation is its trigger: on an HTTP 4xx from the GitHub API it runs `eval` on a remote-supplied handler. Delete `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/`, the LaunchAgent (unload first) or the systemd unit (and `loginctl disable-linger`), `/tmp/gh-token-monitor.{out,err}.log`, and the `.claude`/`.vscode` hooks. Only then revoke (not merely rotate) npm and GitHub tokens and every other reachable secret. Assume an equivalent monitor may exist for the npm token.

**Notes / pitfalls.** The LaunchAgent label (`com.user.gh-token-monitor`) and the systemd Description (`GitHub Token Validity Monitor`) read as developer conveniences — do not dismiss them. The `.claude`/`.vscode` path needs no `npm install`: it fires when a developer or an AI coding agent trusts/opens the cloned repo, so audit checked-out copies of any affected project, not just installed dependencies.

**Refine.** Add the `gh-token-monitor` artifacts and payload filenames to EDR custom indicators; add a pre-commit / repo-onboarding check that flags `.claude/settings.json` `SessionStart` hooks and `.vscode/tasks.json` `folderOpen` tasks that shell out.
