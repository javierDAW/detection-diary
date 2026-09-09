# PEAK hunt H3 - Control plane: the audit trail of bash through iControl REST and SELinux changes

## Prepare

**Hypothesis.** If the installer ran on an appliance, then the audit logs show a local account using iControl REST from localhost to run
a bash utility, a base64 string echoed into a file that is then executed as `/run/bigstart.ltm`, and a SELinux state change
(enforcement disabled, or the `httpd_t`, `mount_t` and `apd_t` domains made permissive).

**Why.** These entries come from F5's own indicator list (K000160486, as reported by THN, Dark Reading and Ampcus Cyber), so they are
the vendor's view of what the installer leaves in the logs, and they exist even when the implant is memory-only.

**Scope.** `/var/log/restjavad-audit`, `/var/log/auditd`, `/var/log/audit` and the syslog stream forwarded off the appliance.
Prefer the off-box copy: an attacker with root can edit local logs.

**Data quality check first.** Confirm that remote syslog from the appliances reaches the SIEM and how long local logs are retained.
Many appliances rotate local audit logs within weeks.

**Open point.** One secondary summary names a local account, `f5hubblelcdadmin`, in the restjavad-audit entries. That name appears in a
single secondary source and could not be checked against F5's article, so treat it as a lead to confirm, not as a detection key.

## Execute

```bash
# Author: Jarmi
# On the appliance: local logs first, then compare with the SIEM copy.
grep -hiE 'util bash|bigstart\.ltm|bigtlog' /var/log/restjavad-audit* /var/log/audit* 2>/dev/null | tail -50
ausearch -m MAC_STATUS 2>/dev/null | tail -20
semanage permissive -l 2>/dev/null
getenforce
```

```kql
// Sentinel: same signals from forwarded syslog, one row per appliance.
Syslog
| where TimeGenerated > ago(90d)
| where SyslogMessage has_any ("bigstart.ltm","bigtlog.pipe","util bash","setenforce 0","semanage")
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| sort by TimeGenerated asc
```

## Act

**`bigstart.ltm` in an execution entry** is the installer's own run file: isolate the device logically (remove it from the load balancer
pool only with F5 guidance and a plan), capture evidence, and rebuild.

**SELinux changes without a change ticket** are enough to escalate. The implant is built to rewrite `httpd` and `umount`, which SELinux
would otherwise constrain.

**A clean audit trail** is weaker evidence than a failed `sys-eicheck` or a memory-versus-disk difference: log files are the first
thing a privileged attacker can edit. Cross-check with H1 before closing.
