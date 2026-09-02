# PEAK hunt H3 - Peer-to-peer behaviour baseline and a clipboard integrity canary

## Prepare

**Hypothesis.** If a Sality bot is on an endpoint, the host shows peer-to-peer behaviour that no approved application explains: UDP
traffic to dozens of unrelated public addresses on a 40-minute rhythm. And if the infection delivered EggJagger, any cryptocurrency
address that a user copies on that host may be silently replaced before it is pasted.

**Why third.** The two halves cover what H1 and H2 cannot: the network behaviour of an infection whose sinkhole traffic is not logged,
and the financial effect, which is where the operator made its money (CrowdStrike estimates at least 12.1 million roubles, about
150,000 US dollars, from EggJagger, which monitors the clipboard for wallet addresses and swaps in addresses the operator controls).

**Mechanics to know.** Per CrowdStrike, bots re-check their stored peers every 40 minutes, responsive peers gain reputation and silent
ones are purged, and there is no authentication of peers. A defender can therefore expect a regular rhythm from an infected host.

**Data quality check first.** For the network half you need per-process UDP flow telemetry. For the clipboard half you need
permission to run a harmless test on endpoints of staff who handle cryptocurrency or payment details.

## Execute

```kql
// Network half: non-network processes with UDP fan-out in many distinct 40-minute cycles.
let known_udp_processes = dynamic(["<add_known_udp_processes>"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol =~ "Udp" and RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ (known_udp_processes)
| summarize Peers = dcount(RemoteIP), Cycles = dcount(bin(Timestamp, 40m)), Events = count()
        by DeviceName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| where Peers >= 50 and Cycles >= 20
| sort by Peers desc
```

```powershell
# Author: Jarmi
# Clipboard half: harmless canary. Puts the BIP-173 documentation test vector on the clipboard, waits, and reports if it changed.
# The address is a published test vector (never send funds to it), and its format matches what a clipboard hijacker looks for.
$canary = 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'
Set-Clipboard -Value $canary
Start-Sleep -Seconds 20
$now = Get-Clipboard -Raw
if ($now.Trim() -ne $canary) { Write-Output "ALERT: clipboard content changed to: $($now.Trim())" } else { Write-Output "clipboard unchanged" }
```

## Act

**A process with sustained UDP fan-out and no approved purpose** should be triaged as a bot candidate: capture the executable, its
signature status, parent and the first time it appeared, then compare with H1 and H2 on the same host.

**A canary that changes** means something on that host is rewriting clipboard contents. Isolate the machine, do not paste any
real payment address from it, and verify any recent transfer by checking the destination address on the receiving side.

**Finance and crypto staff** should confirm the first and last characters of every pasted address out of band, whatever the
canary result, because the canary only proves absence of a hijacker at the moment of the test.

## Knowledge

Record the approved UDP-heavy applications per role and the roles that handle payment addresses. Schedule the canary on those
roles' machines as a recurring low-cost integrity check.
