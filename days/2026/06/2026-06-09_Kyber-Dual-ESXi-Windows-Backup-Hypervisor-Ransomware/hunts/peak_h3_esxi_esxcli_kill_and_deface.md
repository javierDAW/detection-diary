# PEAK Hunt H3 — ESXi esxcli VM kill burst + management-interface defacement

**Hypothesis.** If the Kyber ESXi/Linux variant ran on a host, then ESXi logs will show a burst of `esxcli vm process list` followed by repeated `esxcli vm process kill type=soft world-id <id>`, and overwrites of `/etc/motd` and the hostd docroot index pages (`/usr/lib/vmware/hostd/docroot/index.html`, `/usr/lib/vmware/hostd/docroot/ui/index.html`) with the ransom note, before `.xhsyw` files appear under `/vmfs/volumes`.

**ATT&CK.** T1489 (Service Stop), T1491.001 (Internal Defacement), T1021.004 (Remote Services: SSH).

## Prepare

- Telemetry: ESXi `shell.log` and `hostd.log` forwarded as syslog to the SIEM (Sentinel `Syslog`), or collected during IR.
- Scope: all ESXi hosts. Baseline legitimate VM-shutdown automation (usually vim-cmd / vCenter, rarely `esxcli vm process kill`).

## Execute

```kql
Syslog
| where TimeGenerated > ago(14d)
| extend Msg = tolower(SyslogMessage)
| where Msg has "vm process kill" or Msg has "/etc/motd" or Msg has "docroot/index.html" or Msg has "docroot/ui/index.html"
| summarize Kills = countif(Msg has "vm process kill"),
            Deface = countif(Msg has "motd" or Msg has "docroot"),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by HostName, bin(TimeGenerated, 30m)
| where Kills >= 3 or Deface >= 1
| order by Kills desc
```

Offline / on-host triage:

```bash
grep -E "esxcli vm process (list|kill)" /var/log/shell.log
for f in /etc/motd /usr/lib/vmware/hostd/docroot/index.html /usr/lib/vmware/hostd/docroot/ui/index.html; do
  echo "== $f =="; head -c 400 "$f"; echo; done
find /vmfs/volumes -maxdepth 3 -name '*.xhsyw' 2>/dev/null | head
```

## Analyze

- A run of soft-kills across many world-ids immediately before datastore file changes is the ESXi ransomware fingerprint; the defacement of `/etc/motd` and the hostd docroot confirms Kyber's ELF specifically.
- Check SSH session open/close timing around the kill burst (the binary uses fork/`setsid` to keep running after the session closes).

## Act

- If confirmed: pull ESXi SSH/management access, snapshot host state, and preserve `shell.log`/`hostd.log` and a `.xhsyw` sample with its `.cryptdata_backup` before any reboot (a reboot can finalize VM-state corruption).
- Restore VMs only from verified-clean offline copies; restore the defaced ESXi management files from a known-good source; enforce least-privilege + MFA on ESXi SSH/management.
