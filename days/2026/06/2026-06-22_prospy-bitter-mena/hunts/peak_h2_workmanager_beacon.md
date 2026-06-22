# PEAK Hunt H2 — ProSpy WorkManager Periodic Beacon in Network Flows

**Hypothesis:** If ProSpy uses Android WorkManager to schedule periodic data collection and C2 polling, then network flow analysis from mobile devices will show regular HTTPS POST bursts to low-reputation domains at sub-hourly intervals, with consistent payload size distribution matching contact/SMS JSON followed by binary file uploads.

**MITRE:** T1071.001 (Application Layer Protocol: Web Protocols), T1041 (Exfiltration Over C2 Channel)

**Priority:** Medium

---

## Prepare

**Scope:** Mobile device network flows from enterprise MDM / NAC / NGFW for Android devices; focus on managed devices and BYOD enrolled in EMM.

**Data sources required:**
- NetFlow / IPFIX from NGFW or NAC for mobile device subnets
- DNS query logs for mobile device range
- MDM/EMM console: installed app inventory, permission grants, WorkManager job history (if MDM agent supports)
- Proxy logs (if mobile traffic is proxied)

**Time window:** 7-day lookback (WorkManager repeat intervals may vary 15 min to several hours)

---

## Execute

### Step 1 — Identify mobile devices with HTTPS POST bursts to external IPs

```kql
// Defender XDR — DeviceNetworkEvents scoped to mobile-adjacent processes
// Adapt for your MDM-enrolled device naming convention
DeviceNetworkEvents
| where ActionType == "HttpConnectionInspected"
| where InitiatingProcessFileName in ("com.android.vending", "<add_known_browser>")
    or RequestUri contains "/v3/"
| summarize
    PostCount = countif(ActionType == "HttpConnectionInspected"),
    UniqueHosts = dcount(RemoteUrl),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceId, DeviceName, RemoteUrl, bin(Timestamp, 1h)
| where PostCount > 3 and UniqueHosts == 1  // Same host, repeated — beacon-like
| sort by PostCount desc
```

### Step 2 — Correlate burst timing to WorkManager periodic intervals

```python
# Python: detect periodic interval from flow timestamps
# Feed: list of HTTPS POST timestamps to a single remote host from one device

import statistics

timestamps = [<epoch_ts_1>, <epoch_ts_2>, <epoch_ts_3>, ...]  # from step 1 output

intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
if len(intervals) > 2:
    mean_interval = statistics.mean(intervals)
    stdev_interval = statistics.stdev(intervals)
    cv = stdev_interval / mean_interval if mean_interval else 0
    print(f"Mean interval: {mean_interval:.0f}s ({mean_interval/60:.1f}min)")
    print(f"CoV: {cv:.2f} — {'BEACON-LIKE' if cv < 0.25 else 'variable'}")
```

WorkManager minimum interval: 900s (15 min). ProSpy is observed using periodic intervals; CoV < 0.25 indicates scheduled behaviour.

### Step 3 — Check DNS for C2 domain resolution from same device

```bash
# DNS log grep for known C2 patterns from suspect device IP
# Adapt to your SIEM / DNS log format
grep -E "(sgnlapp\.info|treasuresland\.cc|relaxmode\.org|track-portal\.co|totokapp\.info|totok-pro\.io|regularsports\.org)" /var/log/dns/*.log \
  | grep "$(echo <DEVICE_IP>)"
```

### Step 4 — MDM package inventory check

Pull package list from MDM for flagged device and compare against known ProSpy package names:
```
com.chatbot.botim
com.chat.connect
the.messenger.bot
al.totok.chat
org.thoghtcrime.securesms
ae.totok.chat
im.thebot.mesenger
```

---

## Analyze

**Positive signal indicators:**
- Periodic HTTPS POST bursts from same source IP / device to same external host at ~15-60 minute intervals
- CoV of inter-POST intervals < 0.25 (consistent scheduling)
- Destination domain newly registered (< 90 days) or absent from Alexa/Tranco top-1M
- Device has side-loaded APK with suspicious package name (MDM alert or `/proc/net` check)
- POST payload sizes cluster into two groups: small JSON (~2-10 KB for contacts/SMS) and large binary (~100 KB+ for file exfil)

**Tuning:**
- Exclude enterprise MDM agents and known push-notification senders (FCM, APNs endpoints)
- Exclude known business chat apps (Teams, Slack mobile) that have regular heartbeat patterns

---

## Act

- **Isolate device:** Pull from corporate network, enforce airplane mode, initiate ADB forensic capture.
- **MDM remote action:** Trigger MDM compliance check; if non-compliant, quarantine device profile.
- **Block C2 range:** Add confirmed remote IPs to NGFW deny list; submit to ThreatFox.
- **Escalate to IR:** If device belongs to high-risk user (journalist, civil society, policy staff), escalate immediately and engage Access Now DSH if applicable.

---

## References

- [Android WorkManager documentation](https://developer.android.com/topic/libraries/architecture/workmanager)
- [Lookout ProSpy detailed analysis — WorkManager scheduling](https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire)
- [PEAK threat hunting methodology](https://www.sans.org/white-papers/peak-hunting/)
