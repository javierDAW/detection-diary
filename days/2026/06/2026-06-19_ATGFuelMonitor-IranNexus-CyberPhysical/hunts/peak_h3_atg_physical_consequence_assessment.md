# PEAK Hunt H3 — ATG Physical Consequence Assessment: Alert Suppression and Reading Manipulation

**Case**: Iran-nexus ATG cyber-physical campaign (IC3-260602)
**Date**: 2026-06-19
**Author**: Jarmi
**Slot**: #22 OT physical / cyber-physical
**MITRE**: T1562.001, T0831, T0836, T0816

---

## Hypothesis

The physical-consequence dimension of this campaign is that an attacker who suppresses leak
detection alerts or manipulates tank level readings removes the operator's ability to detect
a real physical problem (fuel leak, overflow). This is the cyber-physical pivot: a digital
configuration change produces a physical safety gap. Incident responders must assess not just
whether the system was compromised but whether any physical process was affected.

**Goal**: determine if any ATG devices have suppressed alarms, manipulated thresholds, or
missing audit trails that indicate physical consequence risk requiring safety-team escalation.

---

## Telemetry Sources

- ATG management system (Veeder-Root SMS, FuelsManager, OilDoc) — direct query
- Physical site inspection records
- Fuel inventory reconciliation logs (paper or ERP)
- Safety management system (if deployed)
- OT historian data (fuel level trends, temperature profiles)

---

## Hunt Queries

### Step 1 — Enumerate all ATGs with any alarm currently disabled

```bash
# On ATG management workstation (Veeder-Root Fuel-Site Suite or equivalent)
# Export alarm configuration report for all sites and filter disabled
# Replace with vendor-specific CLI or API call
for site in $(list-sites); do
  site-alarm-status --site "$site" --format csv | grep "DISABLED\|SUPPRESSED\|BYPASSED"
done

# Alternatively, if ATG supports TLS ASCII command protocol:
# Connect via nc to 10001/tcp and send function code i10100 (in-tank inventory)
# then i30100 (sensor alarms) to enumerate current alarm state
```

### Step 2 — Check fuel level trend for anomalies (data manipulation indicator)

```kql
// If historian data in Sentinel or Azure Data Explorer
let expected_range = 1000;  // maximum legitimate level change in gallons per hour
datatable(SiteName: string, TankId: string, ReadingTime: datetime, FuelLevel: real)
    ["<add_historian_table_name>"]  // replace with actual historian table
| sort by SiteName, TankId, ReadingTime asc
| extend LevelDelta = FuelLevel - prev(FuelLevel, 1)
| where abs(LevelDelta) > expected_range
| extend Anomaly = case(
    LevelDelta > expected_range, "SUDDEN_INCREASE",
    LevelDelta < -expected_range, "SUDDEN_DECREASE",
    "NORMAL")
| where Anomaly != "NORMAL"
| project ReadingTime, SiteName, TankId, FuelLevel, LevelDelta, Anomaly
| order by ReadingTime desc
```

### Step 3 — Audit trail gap analysis (tampering with audit logs)

```kql
// If ATG syslog forwarded to Sentinel
// Look for time gaps in event stream — attacker may have cleared logs
let atg_events = Syslog
    | where TimeGenerated > ago(30d)
    | where Computer has_any ("<add_known_atg_hostnames>") or Computer startswith "atg-"
    | summarize EventCount = count() by Computer, bin(TimeGenerated, 1h);
atg_events
| sort by Computer asc, TimeGenerated asc
| extend TimeSinceLast = TimeGenerated - prev(TimeGenerated, 1)
| where TimeSinceLast > 2h  // flag gaps > 2 hours (normal event rate for ATG)
| project TimeGenerated, Computer, TimeSinceLast, EventCount
| order by TimeSinceLast desc
```

---

## Physical Assessment Checklist (on-site verification)

If any of the above signals trigger, dispatch physical inspection team:

| Check | Method | Anomaly Indicator |
|-------|--------|-------------------|
| Leak detection status | ATG console alarm display | Any alarm bypassed/suppressed |
| Fuel level vs gauge dip | Manual dip stick measurement | >1% delta from ATG reading |
| Tank overfill protection | Test overfill alarm via ATG | Alarm does not trigger |
| Vapor monitoring | Check vapor sensor readings | Unexpected flat-line readings |
| Delivery reconciliation | Compare delivery records vs ATG log | Unexplained discrepancy |
| Audit log continuity | Review ATG local log | Gaps or deletions |

---

## Actions

1. **If alarm suppressed**: immediately re-enable and test; notify site safety officer.
2. **If level reading anomaly**: conduct manual dip-stick measurement; do NOT rely on ATG display.
3. **If audit log gap**: treat as confirmed tampering; preserve forensic image of ATG storage.
4. **Cross-industry notification**: if confirmed attack, notify Ag-ISAC, Food-ISAC (ATGs also in food/agriculture).
5. **Regulatory**: fuel leak suppression may trigger EPA/state environmental reporting obligations.
