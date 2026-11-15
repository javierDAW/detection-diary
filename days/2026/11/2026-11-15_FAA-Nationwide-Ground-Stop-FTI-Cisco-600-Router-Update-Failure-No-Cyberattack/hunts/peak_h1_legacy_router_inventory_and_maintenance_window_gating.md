# PEAK hunt H1 - End-of-life router inventory and firmware / maintenance-window gating

## Prepare

- **Hypothesis:** our network depends on a population of end-of-life or legacy routers that cannot absorb a patch, feature or traffic increase, and changes reach them without a staged rollout, capacity check or tested rollback.
- **Why:** in the FAA nationwide ground stop of 2026-11-13, the Homeland Security Secretary said new security patches / new equipment introduced into the older system appeared to overwhelm its routers, and the Transportation Secretary called the ATC system very old (CBS News, SecurityWeek 2026-11-14). Senior government sources cited by CBS named Cisco 600 series routers made 2001-2006; other sources described an update to the private ATC communications network causing a reboot, crash and outage. CBS states sources conflict and the root cause is NOT officially confirmed. A November 2023 FAA-commissioned review reportedly called the FAA Telecommunications Infrastructure (FTI) obsolete and TDM-dependent. This hunt does NOT assume our fleet resembles the FAA fleet; it tests whether we carry the same class of risk.
- **Scope:** all routers and switches on paths that carry safety-, life- or revenue-critical traffic (voice, operational data, OT links), including carrier- or contractor-managed equipment.
- **Confidence:** high for inventory facts gathered directly from devices; low for any inference about a third party's fleet.

## Execute

**Data sources:** CMDB / network inventory, live `show version` / `show inventory` collection, vendor end-of-life bulletins, change-management system, syslog in Sentinel (`../kql/k1_syslog_reload_restart_burst_per_device_and_site.kql`, `../kql/k2_syslog_config_change_followed_by_reload_60m.kql`), collected text evidence (`../yara/cisco_ios_crash_reload_triage_evidence.yar`), resource-exhaustion rule (`../sigma/03_network_device_resource_exhaustion_crash_precursors.yml`).

1. Collect hardware model, software version, uptime and last reload reason from every device (read-only commands):

```bash
# Author: Jarmi
# devices.txt: one management IP per line; read-only account; output kept as evidence
while read -r ip; do
  ssh -o BatchMode=yes "<add_readonly_user>@${ip}" 'show version ; show inventory' > "inv_${ip}.txt" 2>&1
done < devices.txt
grep -H -E 'uptime is|System returned to ROM by|System image file' inv_*.txt > inventory_summary.txt
```

2. Join with vendor end-of-life / end-of-support dates; flag devices past last-date-of-support or running software with no maintained train.
3. For each legacy device, record CPU and memory headroom at peak (`show processes cpu history`, `show memory statistics`) and count crash precursors in the last 90 days with the Sigma 03 logic.
4. Pull the last 12 months of changes touching those devices; check each for a staged rollout (canary device first), a capacity check and a tested rollback.
5. Run the YARA rules over archived `show tech-support` / crashinfo files to find prior unexplained reloads.

## Act

- **Findings handling:** a risk register line per legacy device: model, software, EoL date, headroom, prior crashes, criticality of carried traffic, owner (in-house / contractor).
- **Gating controls:** no change to a legacy device without (a) canary on one device, (b) observation period with k1 / k2 running, (c) a pre-staged rollback image and config, (d) a fallback path (redundant circuit, manual voice procedure) confirmed before the window.
- **Contractor-managed networks:** require change notifications and post-change syslog sharing in the contract; an upgrade by a provider is still our outage.
- **Exit criteria:** every critical-path device has a known EoL status, headroom figure and a replacement date; every change to legacy devices in the next quarter follows the gate.

**What this hunt cannot show:** whether any third party (including the FAA / FTI) is exposed, or what actually failed on 2026-11-13; it measures only our own fleet.
