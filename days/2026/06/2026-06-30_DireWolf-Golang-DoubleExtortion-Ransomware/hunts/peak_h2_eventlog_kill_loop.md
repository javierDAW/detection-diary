# PEAK Hunt H2 — Dire Wolf eventlog-kill loop

**Hypothesis (P).** Dire Wolf will terminate the Windows `eventlog` service more than once in a short interval (WMI PID lookup then `taskkill`), optionally followed by `wevtutil cl` of the core channels, to keep local logging blind during encryption.

**Why it works.** Killing the eventlog service is rare in benign operations, and Dire Wolf does it in a repeating loop rather than once. Detecting the repetition catches the family even when a single clear event (1102) is suppressed.

**Enrich (E).** Process-creation telemetry for `taskkill`/`wmic` referencing `eventlog`, and `wevtutil cl`. Count events per host + 5-minute bin.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "taskkill.exe" and ProcessCommandLine has "eventlog")
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "service" and ProcessCommandLine has "eventlog")
     or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl ","clear-log"))
| summarize events=count(), cmds=make_set(ProcessCommandLine,16) by DeviceName, bin(Timestamp,5m)
| where events >= 2
```

**Analyze (A).** Two or more eventlog-termination or clear events in five minutes on one host is high-fidelity. Correlate with H1 on the same host to confirm a ransomware sequence.

**Knowledge (K).** Document any legitimate troubleshooting of the eventlog service. Forward command-line telemetry to the SIEM so scoping does not depend on the local logs the loop is blanking.
