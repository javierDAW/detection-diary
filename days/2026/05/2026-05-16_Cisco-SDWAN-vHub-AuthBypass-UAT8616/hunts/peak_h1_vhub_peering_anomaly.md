# PEAK Hunt H1 — Anomalous vHub peering on Catalyst SD-WAN Controllers

## Hypothesis (H1)

An attacker has exploited CVE-2026-20182 against one of our Catalyst SD-WAN Controllers by
posing as a vHub device in the vdaemon CHALLENGE_ACK handshake. Because the verification
branch for `device_type == 2` is missing in `vbond_proc_challenge_ack()`, the peer was
authenticated without a valid certificate. We expect to find at least one
`control-connection-state-change` syslog entry with `peer-type:vhub` and `new-state:up`
whose `public-ip` does not match any inventoried vHub controller (or any IP at all if the
deployment has no vHubs).

## Why this discriminates

vHub is a niche device role in the SD-WAN fabric. The vast majority of deployments use
vEdge data-plane routers, vSmart controllers, vManage management plane and vBond
orchestrators — not vHubs. In a deployment without a documented vHub topology, ANY vhub
peering event is by definition anomalous. Even in deployments that use vHubs, the
`public-ip` of an exploit attempt comes from attacker-controlled infrastructure and will
not match the operational IP range.

## Expected benign vs malicious

- **Expected benign:** a documented vHub controller in the architecture diagram, peering
  from a documented public IP during a planned operation. Correlated with a change ticket.
- **Expected malicious:** a vhub peering event from a public IP unknown to the inventory,
  occurring outside maintenance windows, followed within 24 hours by a NETCONF SSH login as
  `vmanage-admin` and / or a write to `/home/vmanage-admin/.ssh/authorized_keys`.

## Queries

KQL — Sentinel against the Syslog table where SD-WAN appliances forward logs:

```kql
Syslog
| where SyslogMessage has_all ("VDAEMON","control-connection-state-change","peer-type:vhub","new-state:up")
| extend public_ip = extract(@"public-ip:(\S+)", 1, SyslogMessage)
| project TimeGenerated, Computer, public_ip, SyslogMessage
| where public_ip !in (dynamic(["<add_known_vhub_public_ip>"]))
```

CLI on the controller itself (if direct access is available):

```bash
grep -E "control-connection-state-change.*peer-type:vhub.*new-state:up" /var/log/messages /var/log/vmanage-syslog.log 2>/dev/null
```

## Action on match

1. Snapshot the controller (do not reboot) — capture `/var/log/`, `cli-history`,
   `bash_history`, `wtmp`, `lastlog`, and a `tcpdump` of UDP/12346 if traffic is still flowing.
2. Inspect `/home/vmanage-admin/.ssh/authorized_keys` for unexpected keys appended after the
   timestamp of the suspicious peering event.
3. Inspect `/etc/ssh/sshd_config` for `PermitRootLogin yes` (indicator that the actor escalated
   to root via a downgrade-and-exploit chain with CVE-2022-20775).
4. Audit NETCONF auth logs for `Accepted publickey for vmanage-admin` from non-orchestrator
   sources within the 24 hours following the peering event.
5. If confirmed, isolate the controller from the underlay, rotate `vmanage-admin` keys, and
   patch to the fixed release per Cisco's advisory.

## References

- https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/
- https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/
- https://blog.talosintelligence.com/uat-8616-sd-wan/
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW
