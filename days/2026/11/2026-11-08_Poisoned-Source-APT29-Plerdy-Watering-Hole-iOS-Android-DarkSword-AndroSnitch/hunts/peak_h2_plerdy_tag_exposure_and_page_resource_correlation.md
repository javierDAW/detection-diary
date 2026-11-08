# PEAK hunt H2 - Plerdy SEO Tracker exposure inventory and main.js -> edge-ord loader correlation

## Prepare

- **Hypothesis:** (a) one of our websites embedded the Plerdy SEO Tracker (https://a.plerdy.com/public/js/click/main.js) during 2026-08-27 to 2026-09-03 and therefore served the APT29 loader to its visitors; and/or (b) one of our users browsed a third-party Plerdy-tagged site in that window, and their browser then requested https://edge-ord.clouds-stacks.com/module/5b4c8fea5cbcee273e8d830f52-temfp.js.
- **Why:** Sekoia TDR (2026-11-04) reports the Plerdy script was tampered with appended code (variable `_0x3af331`) that loaded the campaign fingerprinter; third-party script tags without Subresource Integrity (SRI) or a tight Content Security Policy (CSP) inherit the vendor compromise.
- **Scope:** all public sites, marketing landing pages and tag managers we own; user web traffic 2026-08-20 to 2026-09-10.
- **Honesty:** derived from the Sekoia report (2026-11-04) and THN (2026-11-04); no first-hand sample analysis. Referer and user-agent details of victim requests are not published.
- **Confidence:** medium.

## Execute

**Data sources / content:** `kql/k2_mde_plerdy_main_js_then_edge_ord_loader_correlation.kql`, `sigma/02_proxy_plerdy_tracker_followed_by_edge_ord_loader_request.yml` (correlation seed), tag-manager exports, CSP violation reports, web repo history.

1. Inventory Plerdy on our properties (source repos, CMS templates, tag-manager containers):

```bash
# Author: Jarmi
grep -RIn --include='*.html' --include='*.htm' --include='*.php' --include='*.js' --include='*.tpl' --include='*.twig' --include='*.json' -e 'a.plerdy.com' -e 'plerdy' /var/www /srv/www 2>/dev/null
```

2. For each tagged site, check whether the script tag is pinned with `integrity=` (SRI) and whether the CSP `script-src` allowed arbitrary hosts; note that SRI on a vendor-updated script breaks on legitimate updates, so record the vendor change process.
3. Review CSP violation reports (report-uri / report-to collectors) for blocked `script-src` attempts to edge-ord.clouds-stacks.com or static.flux-telemetry.com.
4. Run k2 (endpoint) and implement the Sigma 02 correlation in the SIEM over proxy logs: same client, main.js request then loader request within ~60-120 s.
5. For every correlated client, hand over to H1 to check whether the session progressed to ad.starx-net.com or port 8881.

## Act

- **Findings handling:** list of our sites that served Plerdy in the window (we are a victim-distributor - notify visitors / legal as appropriate), and list of users whose browsers loaded the loader.
- **Hardening:** enforce CSP `script-src` allowlists with reporting, use SRI where the vendor publishes versioned files, review every third-party tag owner and change process.
- **Detections:** keep Sigma 02 correlation and k2 as scheduled analytics for future vendor-script compromises (generic pattern: analytics script followed by an unknown new host).
- **Exit criteria:** all Plerdy embeddings documented with SRI/CSP status; all correlated clients triaged via H1.
