# PEAK hunt H1 - External sessions on OT engineering ports

## Prepare

**Hypothesis.** If an external actor reached our controllers the way the July 2026 water-sector actor did, then at least one
EtherNet/IP, Modbus or S7comm session exists in firewall, carrier or OT-tap data whose source address is not in the engineering
allowlist. The actor needed no exploit and no malware, so this network record is the earliest and possibly the only artifact.

**Scope.** Ninety days of firewall syslog, cellular carrier flow exports, OT tap or span traffic, and VPN session records for every
site with a controller. Ports in scope: TCP 44818 (EtherNet/IP explicit), UDP 2222 (EtherNet/IP implicit), TCP 502 (Modbus TCP),
TCP 102 (S7comm), TCP 9191 (ACEmanager) and TCP 22 (SSH on modems - Dropbear was used on a victim modem in the AA26-097A activity).

**Data quality check first.** Confirm the firewall actually logs accepted flows, not only denies, and that carrier flow records are
retained. If the answer is no, that is the finding: the hunt cannot run and the gap is the deliverable.

**Known-good baseline.** Build the engineering allowlist before hunting: engineering workstation addresses, SCADA and historian
collectors, the integrator's VPN egress, and the vendor maintenance range. Everything else is a candidate.

## Execute

```bash
# 1. Accepted inbound flows to OT ports from non-private sources
grep -E 'dpt=(44818|2222|502|102|9191)' /var/log/firewall.log \
  | grep -Ei '(accept|allow|permit)' \
  | grep -vE 'src=(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  | sed -E 's/.*src=([0-9.]+).*dst=([0-9.]+).*dpt=([0-9]+).*/\1 -> \2:\3/' \
  | sort | uniq -c | sort -rn
```

```bash
# 2. Per-source session profile: first touch, last touch, distinct controllers reached
grep -E 'dpt=(44818|502|102)' /var/log/firewall.log \
  | awk '{ for (i=1;i<=NF;i++) if ($i ~ /^(src|dst|dpt)=/) printf "%s ", $i; print "" }' \
  | sort | uniq -c | awk '$1 > 0' | sort -rn | head -100
```

```kql
// 3. Defender XDR side: any managed device talking to a controller port
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemotePort in (44818, 502, 102, 2222)
| summarize Sessions = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Processes = make_set(InitiatingProcessFileName, 20)
    by DeviceName, RemoteIP, RemotePort
| order by FirstSeen asc
```

## Act

- **Signal.** Any external or non-allowlisted source with a successful session to a controller port is an incident, not a finding.
  Pivot immediately to the controller's own state (hunt H2) and to the gateway logs on that path.
- **Noise.** Carrier-side scanning of the whole address block is constant background; distinguish sweeps (many addresses, one port,
  short window) from interaction (one address, sustained session, bidirectional bytes).
- **Escalate when.** Session duration exceeds a few seconds with bytes in both directions, or a source that only ever appeared once
  matches the timestamps of a controller fault, mode change or program transfer.
- **Product.** An allowlist that is now written down, a documented exposure map per site, and a firewall change request that removes
  every path this hunt discovered. Feed the allowlist into `sigma/02_ot_engineering_protocol_connection.yml`.
