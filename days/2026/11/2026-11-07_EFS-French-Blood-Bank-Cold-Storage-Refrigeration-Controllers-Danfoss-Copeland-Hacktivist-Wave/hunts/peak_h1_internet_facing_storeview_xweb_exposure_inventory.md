# PEAK hunt H1 - Internet-facing Danfoss StoreView / Copeland XWEB Pro exposure and firmware inventory

## Prepare

- **Hypothesis:** at least one refrigeration supervisory controller we own or that a provider operates for us (Danfoss AK-SM 8xxA "StoreView", Copeland XWEB300D PRO / XWEB500D PRO) is reachable from the internet or from enterprise / guest networks, and runs firmware below the fixed builds (Danfoss below 4.2 / R4.3.1, Copeland XWEB Pro 1.12.1 or older).
- **Why first:** exposure is the one precondition we can measure. Censys counted ~1,825 StoreView panels in France on 2026-10-11 and 537 on 2026-10-14, 1,158 of the French ones on firmware below 4.2; CERT-FR alert CERTFR-2026-ALE-012 (relayed by Censys) asks to take them off the internet. Claroty Team82 (2026-08-09) published pre-auth issues for both families (CVE-2025-41450, CVE-2026-25085, CVE-2026-21718, CVE-2026-24663). Health-ISAC (via NPR, 2026-11-06) lists "remove public internet exposure" as the first action after the EFS cold-storage incident.
- **Scope:** blood, plasma, pharmacy, laboratory and food cold rooms; controllers managed by third-party refrigeration providers (the EFS incident hit a provider); store / site networks; vendor remote-access gateways.
- **Confidence:** high for the exposure logic; an exposed panel is NOT evidence of compromise, and no source shows these CVEs were used against EFS.

## Execute

**Data sources:** CMDB / OT asset inventory, provider contracts and network diagrams, external attack-surface scans of our own ranges, firewall logs (`sigma/02_refrigeration_controller_mgmt_reached_from_non_mgmt_network.yml`), Suricata (`suricata/refrigeration_controllers_storeview_xweb_hints.rules`, sid 9950003), Defender for Endpoint (`kql/k2_mde_internal_hosts_to_refrigeration_controller_subnets.kql`).

1. List candidate controllers from inventory and ask every refrigeration provider for the model, firmware and management path of each unit.

2. Fingerprint our own public ranges (authorised scope only) by the published HTTP title:

```bash
# Author: Jarmi
# OWN ranges only; titles per Censys: "Danfoss StoreView" / "Danfoss - StoreView Web"
while read -r ip; do
  t=$(curl -sk --max-time 5 "https://$ip/" -o - | grep -oiE '<title>[^<]*</title>')
  [ -z "$t" ] && t=$(curl -s --max-time 5 "http://$ip/" -o - | grep -oiE '<title>[^<]*</title>')
  echo "$ip,$t"
done < own_public_ips.txt | grep -iE 'storeview|xweb'
```

3. Record firmware evidence: for StoreView, Censys identifies firmware by the HTTP `Last-Modified` header; for XWEB Pro, read the version from the device UI or the provider.

```bash
# Author: Jarmi
curl -skI --max-time 5 "https://<controller_ip>/" | grep -iE '^(last-modified|server):'
```

4. Check reachability from enterprise, guest and VPN segments (one test host per segment) to the controller subnet, covering the web UI and, for XWEB Pro, SSH / Shellinabox.

5. Classify each unit: `EXPOSED_INTERNET`, `EXPOSED_ENTERPRISE`, `SEGMENTED`; and `VULNERABLE_FW` / `FIXED_FW` / `UNKNOWN_FW`.

## Act

- **Findings handling:** table per unit: site, owner / provider, model, firmware, exposure class, management path, remote-access method, alarm path.
- **Immediate mitigation:** remove internet exposure (firewall or provider gateway), put controllers behind an approved jump host, update Danfoss to R4.3.1 or later and XWEB Pro to 1.13 or later, change all controller credentials.
- **Escalation:** every `EXPOSED_INTERNET` unit goes into H2 (configuration-change review) before changes are made, so logs and settings are preserved.
- **Exit / validation criteria:** zero controllers answer from the internet or enterprise / guest networks; 100% of units on fixed firmware or documented as compensated; sid 9950003 silent for 7 days.
- **Caveat:** exposure is not compromise. The vendor and model at EFS were not disclosed.
