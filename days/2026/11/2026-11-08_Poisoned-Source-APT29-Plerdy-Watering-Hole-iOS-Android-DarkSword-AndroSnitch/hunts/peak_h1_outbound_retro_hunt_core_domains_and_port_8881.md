# PEAK hunt H1 - 90-day outbound retro-hunt for Poisoned Source infrastructure and port 8881 exfiltration

## Prepare

- **Hypothesis:** at least one corporate or BYOD device (most likely an iPhone or Android phone on corporate Wi-Fi / VPN) visited a compromised or lookalike site of the "Poisoned Source" campaign and contacted static.flux-telemetry.com, edge-ord.clouds-stacks.com or ad.starx-net.com; a device that reached ad.starx-net.com on TCP 8881 was probably exploited and exfiltrated data.
- **Why:** Sekoia TDR (2026-11-04) attributes the campaign to APT29 (moderate-to-high confidence), discovered mid-October 2026, targeting Ukraine, the US, Czech Republic, Bulgaria and the UK/Europe. All three exploit classes (iOS A/B, Android C) exfiltrate to https://ad.starx-net.com:8881/telemetry/v12.
- **Scope:** 90 days back (covers the Plerdy window 2026-08-27 to 2026-09-03 and the watering holes); web proxy, DNS resolvers, firewall / NetFlow, Defender for Endpoint (incl. mobile), MTD consoles.
- **Honesty:** derived from the Sekoia report (2026-11-04) and THN (2026-11-04); no first-hand sample analysis. IP/ASN data for some rows is medium/low confidence.
- **Confidence:** high for domain hits, medium for IP-only hits.

## Execute

**Data sources / content:** `kql/k1_mde_cef_poisoned_source_domains_and_port_8881_90d.kql`, `sigma/01_proxy_poisoned_source_core_domains_and_exfil_port_8881.yml`, `suricata/poisoned_source_apt29_infrastructure.rules` (sids 9960001-9960003).

1. Run k1 in Defender XDR and Sentinel; export rows grouped by device / source IP.
2. Search DNS resolver logs (Sentinel `DnsEvents` or resolver exports) for the five domains:

```bash
# Author: Jarmi
# Example over exported resolver logs (one query per line)
grep -hiE '(^|\.)(flux-telemetry\.com|starx-net\.com|clouds-stacks\.com|america250\.holiday|theowo\.club)' resolver_*.log | sort | uniq -c | sort -rn
```

3. Search NetFlow / firewall for destination port 8881 to the IP mapped by Sekoia to ad.starx-net.com (195.58.140.105, medium confidence) and for the other campaign IPs; pivot on any internal source.
4. For each hit, determine the device type (iOS / Android / desktop), OS and browser version, and whether the hit included a starx-net stage or 8881 connection (exploitation) or only flux-telemetry / clouds-stacks (profiling only - the fingerprinter returns an empty body to non-phone clients).
5. Identify the referring site from proxy referer data where available (watering-hole attribution of your own exposure).

## Act

- **Findings handling:** per device: first/last seen, indicators hit, stage reached (profiled / staged / exfiltrated), owner, OS version.
- **Escalation:** any 8881 or starx-net hit = assume compromise of the phone: isolate from corporate resources, revoke sessions and cookies of the user (Safari / Chrome cookies were stolen), rotate Wi-Fi PSKs (wifi_passwords.txt / WifiConfigStore.xml collected), reset passwords stored in Chrome Login Data or iCloud Keychain, and preserve a full device backup / sysdiagnose for forensic review.
- **Detections:** keep sids 9960001-9960003 and Sigma 01 in production; feed the domains into DNS blocking.
- **Exit criteria:** all hits classified; zero unexplained 8881 connections; blocklists deployed.
- **Caveat:** a hit outside the campaign window may be sinkhole or research traffic; indicators decay.
