# PEAK hunt H1 - Sinkhole contact is infection: finding Sality bots in egress telemetry

## Prepare

**Hypothesis.** If any machine in our estate is a Sality bot, then since the disruption of 2026-08-31 it has been talking UDP to
188.166.101.148, the defender-operated "lighthouse" address that CrowdStrike put into the poisoned peer lists. The address is not
attacker infrastructure, so a connection to it from an internal host is evidence of infection with almost no false-positive risk.

**Why first.** The sinkhole turned every infected bot that can reach the internet into a self-reporting sensor, and the signal only
exists while the sinkhole runs and while the bots keep trying. It is the cheapest and most precise hunt in the pack, and it has
a shelf life.

**Scope.** Firewall, NetFlow, NAT and EDR network telemetry for 2026-08-31 onward, plus proxy history for the URL pack hosts from the
last v3 and v4 packs. Include guest, lab and BYOD segments, because Sality spreads through shares and removable media and
is most at home on unmanaged machines.

**Data quality check first.** Confirm your telemetry records UDP flows and that NAT logs let you map the translated source back to
an internal host. Many proxies see only TCP; the sinkhole contact is UDP and will be invisible there.

## Execute

```kql
// Defender XDR: any device that touched the sinkhole or a URL pack host since the operation.
let pack_hosts = dynamic(["gatheredovertime.com","imagebucket.biz","theunforgiven.p8.hu","painelwebradiodigital.awardspace.info",
                          "sgwebdesigner.free.fr","www.yonelco.com","pozdravizbeograda.com","highclass.atspace.com","situluimihai.3x.ro"]);
DeviceNetworkEvents
| where Timestamp > datetime(2026-08-31)
| where RemoteIP == "188.166.101.148" or RemoteUrl has_any (pack_hosts)
| summarize First = min(Timestamp), Last = max(Timestamp), Hits = count(), Procs = make_set(InitiatingProcessFolderPath, 10) by DeviceName
| sort by First asc
```

```bash
# Author: Jarmi
# Firewall or conntrack text export: sources that sent anything to the lighthouse address.
grep -h '188\.166\.101\.148' /var/log/firewall/*.log* 2>/dev/null | awk '{print $1, $2, $3}' | sort | uniq -c | sort -rn | head -30
conntrack -L -p udp 2>/dev/null | grep 188.166.101.148
```

```powershell
# Author: Jarmi
# On a suspect Windows host: which process owns UDP sockets, and does it look like a P2P client with no business reason?
Get-NetUDPEndpoint | Where-Object { $_.LocalPort -gt 1024 } |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{ Port=$_.LocalPort; PID=$_.OwningProcess; Name=$p.ProcessName; Path=$p.Path } } |
  Sort-Object Name | Format-Table -AutoSize
```

## Act

**A host that contacted the sinkhole** is infected. Isolate it, collect memory and the infected executables first, and
treat every credential typed on it since infection as stolen. Do not block the sinkhole address on the firewall: that is the
path Shadowserver and ISPs use to notify infected owners, and blocking it only hides your own bots from you.

**A hit only on a URL pack host, path matching** is a bot retrying a dead payload URL; the host is almost certainly infected,
but verify the path before escalating because the free-hosted sites serve unrelated content.

**No hits** means no bot reached the sinkhole through your logged egress. It does not clear hosts that are offline, behind
a different egress, or whose peer lists were never poisoned. Move to H2.

## Knowledge

Record the date range the sinkhole signal covered and the segments whose egress was not logged. Add confirmed hosts to a local
indicator list with first and last contact, and re-run the hunt weekly while the sinkhole is operating.
