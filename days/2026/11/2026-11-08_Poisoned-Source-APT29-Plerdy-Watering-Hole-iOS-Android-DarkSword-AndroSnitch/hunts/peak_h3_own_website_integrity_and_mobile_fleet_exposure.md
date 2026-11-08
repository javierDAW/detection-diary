# PEAK hunt H3 - Own-website integrity for injected loaders and mobile fleet exposure to exploit classes A/B/C

## Prepare

- **Hypothesis:** (a) one of our web properties was turned into a Poisoned Source watering hole by injecting a `window.onload` handler that creates a `<script>` element pointing to `.../module/5b4c8fea5cbcee273e8d830f52-temfp.js`, or by tampering with an existing JS library (as Sekoia saw on a Bulgarian military-related site); and (b) part of our mobile fleet runs OS / browser versions inside the exploited ranges.
- **Why:** Sekoia TDR (2026-11-04) lists compromised legitimate sites in energy (Ukrainian gas production), chemical-industry associations, political parties and defence-related organisations. Exploit ranges: Class A iOS 16.0-17.4 (CVE-2025-43529 + CVE-2024-27834, cookie theft); Class B iOS 18.5 (DarkSword chain: CVE-2025-43529, CVE-2026-20700, CVE-2025-14174, CVE-2025-43510, CVE-2025-43520; full data harvest); Class C Android Chrome 139-145 except 143 (CVE-2026-3910 + CVE-2025-27038, AndroSnitch).
- **Scope:** web roots, CMS templates, bundled JS libraries, CDN origins; MDM / MTD inventory for iOS and Android.
- **Honesty:** derived from the Sekoia report (2026-11-04) and THN (2026-11-04); no first-hand sample analysis. Exact injected code beyond the published snippet is unknown.
- **Confidence:** medium for (a), high for (b) as an exposure measurement (exposure is not compromise).

## Execute

**Data sources / content:** `yara/poisoned_source_apt29_loader_and_androsnitch.yar`, `sigma/03_webserver_fingerprinter_nonce_api_post.yml`, `kql/k3_mde_tvm_chrome_and_web_logs_poisoned_source_exposure.kql`, git history of web repos, file-integrity monitoring, MDM exports.

1. Scan web roots and deployed artifacts with the YARA rule:

```bash
# Author: Jarmi
yara -r -s yara/poisoned_source_apt29_loader_and_androsnitch.yar /var/www /srv/www 2>/dev/null
grep -RIl -e '5b4c8fea5cbcee273e8d830f52-temfp.js' -e 'flux-telemetry' -e 'clouds-stacks' /var/www /srv/www 2>/dev/null
```

2. Diff deployed templates and JS libraries against the source of truth (git / vendor release hashes); flag any library whose bytes differ from the published vendor release, and any recent `window.onload` + `createElement("script")` additions:

```bash
# Author: Jarmi
cd /srv/www/site && git status --porcelain && git diff --stat HEAD
find /srv/www -name '*.js' -newermt '2026-04-01' -printf '%TY-%Tm-%Td %p\n' | sort
```

3. Run k3 part 1 (Chrome 139-145 except 143 on Android) and pull MDM reports for iOS 16.0-17.4 and 18.5; check Lockdown Mode status for high-risk users (journalists, executives, staff with Ukraine / Eastern Europe exposure).
4. Review MTD alerts (Lookout / Zimperium / Defender for Endpoint mobile) for the same devices as hints only.

## Act

- **Findings handling:** (a) any injected loader = our site is a watering hole: preserve the modified files and web logs, remove the injection, rotate CMS / deployment credentials, notify CERT and affected visitors; (b) exposure table per OS / browser version.
- **Mitigation:** force iOS updates beyond the vulnerable builds, enable Lockdown Mode for high-risk users, force Chrome updates on Android, block the campaign domains on mobile DNS / MTD.
- **Detections:** schedule the YARA scan and file-integrity monitoring on web roots; keep k3 as a weekly exposure report.
- **Exit criteria:** zero YARA hits on web roots; all managed devices outside the exploited ranges or documented exceptions.
