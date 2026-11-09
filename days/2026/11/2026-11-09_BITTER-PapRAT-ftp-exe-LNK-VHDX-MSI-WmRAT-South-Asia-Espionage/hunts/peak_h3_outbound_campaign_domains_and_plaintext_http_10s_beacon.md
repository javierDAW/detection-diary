# PEAK hunt H3 - outbound retro-hunt for BITTER campaign domains and the PapRAT plaintext-HTTP 10-second beacon

## Prepare

- **Hypothesis:** at least one internal host contacted BITTER PapRAT / WmRAT infrastructure (netmansrvdns[.]com, rappellingaart[.]com, techtalkhelp[.]com, rivingtonclarks[.]com, goodnfortunes[.]com, gomescareerplans[.]com, chestergreenfarming[.]com, felixfuturenext[.]com) and an infected host shows the PapRAT C++ cadence: plaintext HTTP every 10 s (Rust build: 42 s initial wait, then HTTPS every 5 s).
- **Why:** FortiGuard Labs (2026-11-02) publishes the domains; OffSeq/OTX print URL fragments (techtalkhelp.com/talk.log, www.rivingtonclarks.com/beautiQuewonders/banaNa.php and /banana/, goodnfortunes.com/ucl.php with `svr=%computername%**%username%` and /b99/?kq=%computername%, gomescareerplans.com/docs and /docs/?vid=%computername%, felixfuturenext.com/Epistemological/). The ClientID is username_computername, so URLs may carry host and user names.
- **Honesty:** derived from secondary reports of the FortiGuard Labs (Fortinet) 2026-11-02 research ("BITTER expands its arsenal with PapRAT") as relayed by Infosecurity Magazine, GBHackers, Hackread, Cyberpress, SOC Prime, OffSeq/OTX; the primary Fortinet blog was not read; no first-hand sample analysis. The exact LNK command line, task names, install paths, IPs, C2 ports and user agents are not published. Indicators decay.
- **Scope:** 90 days of DNS resolver, web proxy, firewall / NetFlow and Defender XDR network telemetry.
- **Confidence:** high for the seven FortiGuard-relayed domains; low-medium for felixfuturenext.com (OffSeq/OTX only).

## Execute

**Data sources / content:** `sigma/03_bitter_campaign_domains_proxy_dns.yml`, `kql/k2_mde_campaign_domains_and_c2_urls_90d.kql`, `suricata/bitter_paprat_infrastructure.rules` (sids 9970001-9970003).

1. Run k2; export rows by device and source; note which hosts used `curl.exe` (binary-less ftp chain) versus an unknown process such as `bruzsvc.exe` / `vnces.exe` (RAT).
2. Search resolver logs for the domains:

```bash
# Author: Jarmi
grep -hiE '(^|\.)(netmansrvdns|rappellingaart|techtalkhelp|rivingtonclarks|goodnfortunes|gomescareerplans|chestergreenfarming|felixfuturenext)\.com' resolver_*.log | sort | uniq -c | sort -rn
```

3. Beacon check on proxy / Zeek http logs: per source + host, compute inter-request deltas; a median near 10 s with low jitter over plaintext HTTP (or near 5 s over TLS) is the PapRAT signature. Do the aggregation in the SIEM, not in the rule.

```bash
# Author: Jarmi
# Zeek http.log: ts, id.orig_h, host, uri -> inter-request deltas listed per (src, host); eyeball or compute the median in the SIEM
zeek-cut ts id.orig_h host uri < http.log | awk '{k=$2" "$3; if (k in last) print k, $1-last[k]; last[k]=$1}' \
  | sort | awk '{d[$1" "$2]=d[$1" "$2]" "$3} END {for (k in d) print k, d[k]}' | head
```

4. Look for URIs with the published fragments on any host (the domains may rotate while paths persist) and for query strings carrying a local computer or user name.
5. Enable the Suricata sids on egress sensors for forward coverage.

## Act

- **Findings handling:** per source: first / last seen, indicators hit, cadence, initiating process, user and computer names leaked in URIs.
- **Escalation:** a regular 10 s / 5 s beacon or a hit on a C2 path = compromised host; hand to H1 / H2 for root cause, isolate, block the domains at DNS and proxy, and preserve proxy logs (they record operator command retrieval and `abc.pdf` uploads).
- **Detections:** keep Sigma 03 and sids 9970001-9970003 in production; feed the domains to DNS blocking with an expiry review.
- **Exit criteria:** every hit classified (true positive, sandbox / TI research, sinkhole); no unexplained periodic plaintext-HTTP beacons to new domains.
- **Caveat:** attacker infrastructure may be defunct or sinkholed; re-validate before treating a hit as live. Indicators decay.
