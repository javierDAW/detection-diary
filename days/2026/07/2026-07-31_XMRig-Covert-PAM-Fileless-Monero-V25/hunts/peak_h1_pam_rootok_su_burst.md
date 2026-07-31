# PEAK Hunt H1 - pam_rootok Root-to-User su Burst

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If the actor abuses `pam_rootok` + `su` for a forensic smokescreen, then a root process spawns `su` into several distinct non-root local users within a short window, with no preceding failed-authentication events.

## Prepare

- **ATT&CK:** T1556 (Modify Authentication Process), T1078.003 (Valid Accounts: Local Accounts).
- **Data sources:** Linux auditd (`execve` of `/bin/su`, `syscall=setuid`), `/var/log/auth.log` or `secure` (`session opened for user X by (uid=0)`), Defender for Endpoint `DeviceProcessEvents`.
- **Scope:** Servers reachable from third-party/partner trust paths; hosts with many local service accounts.

## Execute

```bash
# auth.log: sessions opened by uid=0 (root) into other users, grouped by hour
grep -E "session opened for user .* by .*\(uid=0\)" /var/log/auth.log* 2>/dev/null \
  | grep -vE "for user root" \
  | awk '{print $1, $2, $3}' | sort | uniq -c | sort -rn | head
```

```kql
DeviceProcessEvents
| where FileName == "su" and InitiatingProcessAccountName == "root"
| where ProcessCommandLine !contains "root"
| extend TargetUser = extract(@"su\s+(?:-|-l|--login)\s+(\S+)", 1, ProcessCommandLine)
| summarize DistinctTargets = dcount(TargetUser) by DeviceId, bin(Timestamp, 10m)
| where DistinctTargets >= 3
```

## Act with Knowledge

- **Confirmed malicious:** a burst of root->many-users `su` with no failed-auth precursors, followed by cron writes under those same users. Escalate to H2 (fileless miner) and sweep every user crontab.
- **Benign baseline:** capture which parents (config-management, deploy tooling) legitimately su to service accounts; convert into an allowlist so future bursts stand out.
- **Feed forward:** any target user seen in a burst becomes a pivot for cron and mining-egress hunts.
