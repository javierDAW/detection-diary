# PEAK hunt H2 - Change vs fault vs adversary: reload and crash events without an approved change and without AAA anomalies

## Prepare

- **Hypothesis:** some router reloads or crashes in our environment have no approved change behind them; for each, the evidence (who changed what, from where, authenticated how) separates a failed update or hardware fault from tampering.
- **Why:** the FAA nationwide ground stop of 2026-11-13 shows how fast the question "was this an attack?" becomes public. The Homeland Security Secretary said there was "no indication" of a nefarious act and "we haven't seen any footprints" but did not formally rule it out; the FBI is reportedly probing a software update and reportedly does not think a cyberattack or criminal activity caused it (Bloomberg via SecurityWeek 2026-11-14); NSA, DoD and CISA were reportedly involved. The previous nationwide FAA stop (January 2023) was traced to a contractor deleting files, not a cyberattack. Our goal is to be able to answer the question with evidence, quickly, for our own network.
- **Scope:** every reload, restart, watchdog or memory-failure event on network devices in the last 30 days, plus any outage window reported by users.
- **Confidence:** medium when change, AAA and syslog evidence all agree; low when logging was lost during the event (see H3).

## Execute

**Data sources:** syslog (`../sigma/01_network_device_unexpected_reload_or_restart.yml`, `../sigma/02_network_device_configuration_change.yml`, `../kql/k2_syslog_config_change_followed_by_reload_60m.kql`), TACACS+ / RADIUS accounting, change tickets, config archive (RANCID / Oxidized / NCM), wire hints (`../suricata/faa_fti_router_update_failure_syslog_hints.rules`), crash evidence (`../yara/cisco_ios_crash_reload_triage_evidence.yar`).

1. List all reload / crash events per device (k1 or Sigma 01 / 03 output).
2. Run k2 to pair each event with configuration changes in the preceding 60 minutes; record user, line and source.
3. For each event, answer the separating questions:

| Question | Change-induced fault | Hardware / capacity fault | Possible tampering |
|---|---|---|---|
| Approved ticket covering device and time? | yes | not needed | no |
| Config change before failure? | yes, by known admin / automation | usually no | yes, by unknown or unusual account, line or source |
| AAA accounting matches syslog CONFIG_I? | yes | n/a | gaps, local-account use, failed then successful logins |
| Config diff vs archive | matches the planned change | no diff | unexplained ACL / route / user / logging changes |
| Image / boot variable changed? | only as planned | no | unexpected image, boot variable or checksum mismatch |
| Pattern across fleet | follows rollout order | random / single device | simultaneous on unrelated devices, or follows no rollout |

4. Diff running configuration against the last archived version; verify the running image checksum against the vendor published hash for that release (`verify /md5` on the image file).
5. Pull AAA accounting for the device for the event window and the 24 hours before; look for local-account logins, logins from non-jump-host sources and logging-host changes.

```bash
# Author: Jarmi
# Compare archived and current configs (Oxidized / RANCID export), ignoring timestamps
diff <(grep -vE '^(!|ntp clock-period|Building configuration)' archive/<add_device>.cfg) \
     <(grep -vE '^(!|ntp clock-period|Building configuration)' current/<add_device>.cfg)
```

## Act

- **Findings handling:** classify each event as change-induced, hardware / capacity, or unexplained; unexplained events escalate to incident response with preserved crashinfo, show tech and AAA logs.
- **Change-induced:** roll back, reopen the change, add the device to the H1 gating list.
- **Possible tampering:** isolate management plane access, preserve evidence before reload, rotate device and AAA credentials, review recent logins network-wide.
- **Exit criteria:** every event in scope has a classification backed by at least two independent evidence sources (ticket plus AAA, or AAA plus config diff).

**What this hunt cannot show:** an attacker with full admin access who uses an approved account inside an approved window and clears local logs can look like a change-induced fault; absence of footprints is not proof of absence, as the FAA officials themselves noted.
