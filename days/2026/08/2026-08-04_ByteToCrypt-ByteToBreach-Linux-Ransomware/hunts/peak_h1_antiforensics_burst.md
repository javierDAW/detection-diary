# PEAK Hunt H1 - ByteToCrypt Fixed Anti-Forensics Command Burst

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If ByteToCrypt ran on a host, then a single parent process executed the fixed nine-command anti-forensics block (kill logging daemons, disable audit, clear ring buffer, wipe `/var/log`, truncate utmp/lastlog, clear history) within seconds, regardless of whether encryption succeeded.

## Prepare

- **ATT&CK:** T1489 (Service Stop), T1562.001 (Impair Defenses), T1070.002 (Clear Linux System Logs), T1070.003 (Clear Command History).
- **Data sources:** Linux auditd `execve`, EDR process telemetry, and any log/telemetry forwarded off-host BEFORE the wipe.
- **Scope:** all Linux hosts; prioritize datastore/hypervisor hosts and anything with a recent bulk `.encrypted` file event.

## Execute

```bash
# The fixed anti-forensics commands (search surviving off-host telemetry / EDR)
grep -REn 'killall -9 rsyslogd syslog-ng auditd systemd-journald|auditctl -e 0|dmesg -C|truncate -s 0 /var/(run/utmp|log/lastlog)' 2>/dev/null

# Signs the block already ran: empty/zeroed records and missing logs
stat -c '%s %n' /var/run/utmp /var/log/lastlog 2>/dev/null   # size 0 is suspicious
ls -la /var/log /var/log/journal /etc/audit 2>/dev/null      # emptied dirs
systemctl is-active rsyslog auditd systemd-journald 2>/dev/null
```

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("killall -9 rsyslogd", "auditctl -e 0", "dmesg -C",
    "rm -rf /var/log", "truncate -s 0 /var/run/utmp", "truncate -s 0 /var/log/lastlog")
| summarize DistinctCmds = dcount(ProcessCommandLine), Cmds = make_set(ProcessCommandLine, 20)
    by DeviceId, bin(Timestamp, 5m)
| where DistinctCmds >= 2
```

## Act with Knowledge

- **Confirmed malicious:** two or more of the fixed commands from one parent in a tight window, especially co-occurring with `.encrypted` renames or a ransom `note` write.
- **Benign baseline:** decommissioning scripts and aggressive log rotation can touch `/var/log`; they rarely kill auditd AND truncate utmp AND clear history together.
- **Feed forward:** the owning process/CWD feeds H2 (datastore blast radius); confirmation that logs were wiped raises the priority of off-host collector review and RAM capture.
