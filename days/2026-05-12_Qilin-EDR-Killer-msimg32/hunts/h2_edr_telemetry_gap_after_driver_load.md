# Hunt H2 — EDR telemetry gap immediately after a kernel driver load

## Hypothesis

The Qilin / Warlock loader reaches Stage 4 by loading `rwdrv.sys` and then `hlpdrv.sys`. Within seconds of loading the latter, the EDR agent on the host is terminated through `IOCTL 0x2222008`. The behavioural side-effect that the SIEM sees is a sudden drop in the volume of `DeviceProcessEvents` (or equivalent) coming from the affected host.

## Why this discriminates

- A live, healthy endpoint with a normal user session emits dozens of process events per minute.
- Hosts that are powered off, rebooted or sleeping show a clean termination of telemetry, not a drop in mid-session.
- A driver-load event followed within 5-15 minutes by quiescence in the same host's process telemetry is structurally rare and is the classic shape of an EDR kill mid-attack.

## Expected benign vs malicious

- **Benign:** kiosk hosts or rarely-used build agents with naturally low event volume; planned reboots that show clean cessation rather than rolling silence.
- **Malicious:** workstation host loading `rwdrv.sys` / `hlpdrv.sys` from `Temp` or `ProgramData`, followed by event count dropping to near zero while the host is still pingable on the network.

## Action on match

1. Network-isolate the host. Do not power off.
2. Acquire the RAM image — the EDR driver list and Stage 4 PE only live in memory.
3. Hunt across the rest of the fleet for the same driver hashes; the operator usually stages on multiple hosts in parallel.
4. Force a fresh EDR install only after re-image; the existing agent process is dead and cannot be revived.

## Query — Defender XDR

```kql
let suspicious_drivers = DeviceImageLoadEvents
    | where Timestamp > ago(24h)
    | where FileName in~ ("rwdrv.sys", "hlpdrv.sys")
    | project DeviceName, drvTime=Timestamp;
let telemetry_quiescence = DeviceProcessEvents
    | where Timestamp > ago(24h)
    | summarize eventCount=count() by DeviceName, bin_5m=bin(Timestamp, 5m)
    | where eventCount < 3;
suspicious_drivers
| join kind=inner telemetry_quiescence on DeviceName
| where bin_5m between ((drvTime) .. (drvTime + 15m))
```

## Reference

- [Qilin EDR killer infection chain — Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/)
- [Qilin and Warlock Ransomware Use Vulnerable Drivers — The Hacker News](https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html)
