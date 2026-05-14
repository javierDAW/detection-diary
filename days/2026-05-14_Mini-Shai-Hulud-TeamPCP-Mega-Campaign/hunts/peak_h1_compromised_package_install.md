# Hunt H1 — Provenance-Clean Poison: Package Install During Mini Shai-Hulud Distribution Window

**Hypothesis (PEAK framework)**

TeamPCP compromised 170+ npm/PyPI packages between 2026-05-11 19:20 UTC and 2026-05-12 ~14:00 UTC.
Any host that installed @tanstack, @uipath, @mistralai/mistralai, guardrails-ai, or opensearch packages
during that window may have received the malicious transformers.pyz payload, even though the packages
carried valid SLSA Build Level 3 provenance (first documented case of SLSA forgery in a supply-chain worm).

**Why this discriminates**

- The malicious versions were indistinguishable from legitimate ones via npm audit signatures or SLSA checks
- The install window is narrow and historically bounded (19:20 UTC May 11 to ~14:00 UTC May 12)
- Post-install behaviour is highly anomalous: python3 reads 4+ credential files within 5 minutes of npm/pip execution
- The gh-token-monitor daemon is unique to this worm — no legitimate software creates that service name

**Expected benign vs. malicious**

| Signal | Benign | Malicious |
|--------|--------|-----------|
| Install timestamp | Any time | 2026-05-11 19:20 → 2026-05-12 14:00 UTC |
| Package version installed | Clean version (not in IOC list) | Compromised version (check lockfile) |
| Post-install network egress | Registry, CDN, known services | 83.142.209.194, git-tanstack.com, getsession.org |
| Credential file reads post-install | None or expected tooling | Burst ≥ 4 distinct paths within 5 min |
| /tmp/transformers.pyz present | Absent | Present — YARA match |
| gh-token-monitor service | Absent | Present in systemd or LaunchAgents |

**Hunt query — Defender XDR**

```kql
// Step 1: find installs during the attack window
let MaliciousWindowStart = datetime(2026-05-11T19:20:00Z);
let MaliciousWindowEnd   = datetime(2026-05-12T14:00:00Z);
let CompromisedPackages  = dynamic([
    "@tanstack", "@uipath", "@mistralai",
    "guardrails-ai", "mistralai==2.4.6",
    "@opensearch-project/opensearch"
]);
DeviceProcessEvents
| where Timestamp between (MaliciousWindowStart .. MaliciousWindowEnd)
| where ProcessCommandLine has_any (CompromisedPackages)
| where ProcessCommandLine has_any ("npm install", "pip install", "pip3 install",
                                    "yarn add", "pnpm add")
| project DeviceName, AccountName, Timestamp, ProcessCommandLine
| order by Timestamp asc
```

**Hunt query — auditd / Linux (bash)**

```bash
# Check if transformers.pyz was downloaded or executed
journalctl --since "2026-05-11 19:00" --until "2026-05-12 15:00" \
    | grep -E 'transformers\.pyz|git-tanstack|83\.142\.209\.194'

# Check systemd for gh-token-monitor
systemctl list-units --all | grep token-monitor

# Check for gh-token-monitor in LaunchAgents (macOS)
find ~/Library/LaunchAgents /Library/LaunchAgents -name "*token-monitor*" 2>/dev/null

# Check npm lockfiles for compromised versions
# (run in each project repo that uses the affected packages)
grep -rE '"@tanstack/[^"]+": "\d+\.\d+\.\d+"' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
```

**Action on match**

1. Isolate the host from network **before** revoking any GitHub/npm tokens (revocation triggers gh-token-monitor destructor)
2. Capture RAM image (volatility) and `/tmp/transformers.pyz` if present for forensic analysis
3. Run YARA rule `MiniShaiHulud_TransformersPyz_TeamPCP_2026` across `/tmp` and npm cache
4. Stop and disable gh-token-monitor daemon before token revocation
5. From a clean host: revoke all tokens (GitHub, npm, cloud) accessible from the compromised machine
6. Audit cloud provider logs (CloudTrail, GCP audit, Azure Monitor) for activity from the exfiltrated credentials
7. For crypto wallets: move funds on-chain before host cleanup — assume keystores exfiltrated
8. Rotate all credentials, re-image the host, reinstall packages from verified clean lock file

**References**

- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- https://snyk.io/blog/tanstack-npm-packages-compromised/
