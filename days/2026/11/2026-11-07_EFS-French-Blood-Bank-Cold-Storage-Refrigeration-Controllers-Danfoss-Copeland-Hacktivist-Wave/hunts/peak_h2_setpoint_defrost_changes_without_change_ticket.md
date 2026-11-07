# PEAK hunt H2 - Setpoint and defrost-threshold changes not matched by change tickets, correlated with an independent temperature probe

## Prepare

- **Hypothesis:** someone changed temperature setpoints, alarm limits or defrost thresholds / modes on our refrigeration controllers outside an approved change, typically at night, and the independent probe or alarm recorded the resulting temperature excursion.
- **Why:** this is the observed impact. At EFS (attack began overnight 2026-11-02, confirmed 2026-11-03) temperature and defrost thresholds on plasma refrigerators were raised to extremely high levels; monitoring and alarms detected the deviation and staff intervened before the blood was spoiled (Medical Device Network / NPR, 2026-11-06). In the October 2026 wave French supermarket refrigeration was switched to defrost on the night of 2026-10-11 (Censys). Claroty's lab demo altered the setpoint display and disabled fans over serial Modbus to an XR60CX field controller, so the controller's own display may not be trustworthy.
- **Scope:** every unit from H1, prioritising `EXPOSED_*` units and units holding blood, plasma, vaccines or medicines.
- **Confidence:** medium for a positive hit (unapproved parameter change plus physical excursion); low for a negative result, because controller event logs may be short, overwritten or editable by an attacker with admin access.

## Execute

**Data sources:** controller alarm / event history and parameter exports, supervisory software history, the independent temperature monitoring system (separate probes and data loggers), CMMS / change tickets, reverse-proxy logs (`kql/k1_syslog_nginx_storeview_xml_cgi_untrusted_sources.kql`), web logs (`sigma/01_danfoss_storeview_xml_cgi_from_untrusted_source.yml`, `sigma/03_vendor_remote_access_posts_to_controller_web_ui.yml`).

1. Export current parameters (setpoints, alarm high / low limits, defrost termination temperature and schedule, fan state) from each controller and compare with the last known-good baseline or provider commissioning sheet.

2. Pull the independent probe history and list excursions:

```bash
# Author: Jarmi
# probe_export.csv: timestamp,unit_id,temp_c  (from the independent logger, NOT the controller)
awk -F, -v LIMIT="<add_unit_high_limit_c>" 'NR>1 && $3+0 > LIMIT {print $1","$2","$3}' probe_export.csv \
  | sort -t, -k2,2 -k1,1 > excursions.csv
wc -l excursions.csv
```

3. For each excursion window, list controller parameter changes and web-management POSTs in the preceding 12 hours, with source IP and account.

4. Join with change tickets; any parameter change without a ticket, or with a ticket but made from an unexpected source / account / hour, is a finding.

5. Physically verify a sample of units: read the independent thermometer at the cabinet and compare with the controller display.

## Act

- **Findings handling:** timeline per unit: parameter change time, source, account, ticket (y/n), probe excursion start / peak / end, product affected.
- **Immediate response for a confirmed unapproved change:** switch the unit to manual / local control, restore known-good parameters, move product per the cold-chain procedure, preserve controller and proxy logs, rotate all controller and vendor credentials, notify the provider.
- **Escalation:** product-quality / blood-safety officer for any excursion beyond the allowed limit; CERT / national authority for confirmed malicious changes.
- **Exit / validation criteria:** all parameters match the baseline; every change in the review period maps to a ticket; independent alarms tested end-to-end with a forced excursion.
- **Hardening (Health-ISAC via NPR):** hard-wired mechanical cutoffs and independent thermal alarms that software overrides cannot bypass, separated from hospital IT and medical gas monitors; staff trained for manual physical control; offline backups of controller configurations.
