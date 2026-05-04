# PEAK Hunting Hypotheses — C0063 Poland Wiper Attacks

Three hypotheses to run in your environment, anchored to the Sandworm / Static Tundra TTPs documented in CERT Polska + ESET WeLiveSecurity.

---

## H1 — "My fleet has FortiGate exposed AND an unknown GPO startup script."

**Hypothesis.** If we have any GPO Computer-Startup script (`.exe`, `.ps1`, `.bat`, `.cmd`, `.vbs`) registered that is not in the canonical platform-team list, and we recently exposed FortiGate VPN/management without MFA, we may already have a Sandworm/Static Tundra-class operator pre-positioned.

**Sentinel KQL:**

```kql
union DeviceFileEvents, DeviceProcessEvents
| where FolderPath has "\\SYSVOL\\" and FolderPath has "\\Machine\\Scripts\\Startup\\"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(),
            Files=make_set(FileName, 100) by DeviceName
| where FirstSeen > ago(60d)
```

**What you expect.** A short, well-known list of canonical scripts maintained by the platform team. Anything else is to be investigated immediately.

---

## H2 — "There is sustained outbound traffic from an admin host to `:8008` (no TLS, SOCKS-like)."

**Hypothesis.** The rsocx reverse-SOCKS5 used by C0063 keeps the connection open for hours; `duration` is high, `orig_bytes` is low, `resp_bytes` is high, the destination port is non-RFC, and there is no SNI/TLS context.

**Zeek `conn.log`:**

```bash
zeek-cut -d ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes \
         < conn.log | awk '$5 == 8008 && ($6 == "-" || $6 == "socks")'
```

**What you expect.** None — or a very small set of declared egress paths. Anything to a Russian / OBR-class ASN at high port without TLS is to be triaged.

---

## H3 — "GPO admin shows a Kerberos burst within 10 min before a GPO edit."

**Hypothesis.** The Rubeus + GPO weaponization signature is a Kerberos TGS burst followed by a precise SYSVOL edit. The two events should not happen this close in normal operations.

**Sentinel KQL:**

```kql
SecurityEvent
| where EventID == 4769 and Account contains "Admin"
| summarize TGSPerMin=count() by Account, bin(TimeGenerated, 1m), Computer
| where TGSPerMin > 30
| join kind=inner (
    SecurityEvent
    | where EventID == 5136 and ObjectClass == "groupPolicyContainer"
    | project GpoEditTime=TimeGenerated, Account=SubjectAccountName, Computer
  ) on Account, Computer
| where datetime_diff('minute', GpoEditTime, TimeGenerated) between (0 .. 10)
```

**What you expect.** No correlation. If you find one, that's your patient zero candidate.
