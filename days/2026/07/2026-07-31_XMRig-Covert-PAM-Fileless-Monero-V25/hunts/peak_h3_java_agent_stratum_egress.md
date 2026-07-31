# PEAK Hunt H3 - Java/Agent Stratum Mining Egress

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If Stratum traffic is disguised as web-app flows, then a `Java/Agent` User-Agent appears on long-lived TCP from a non-interactive service account, or DNS resolves `unable[.]download`, without any corresponding browser/JVM application footprint.

## Prepare

- **ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1496 (Resource Hijacking).
- **Data sources:** DNS logs, proxy/HTTP logs (User-Agent), NetFlow/Zeek `conn`/`http`, Defender `DeviceNetworkEvents`.
- **Scope:** egress from server subnets and service accounts; exclude known JVM app hosts first, then investigate the remainder.

## Execute

```kql
DeviceNetworkEvents
| where RemoteUrl has "unable.download"
    or (InitiatingProcessCommandLine has "Java/Agent" and InitiatingProcessFileName != "java")
| where InitiatingProcessAccountName != "root" or InitiatingProcessFileName != "java"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
```

```bash
# Zeek/HTTP: Java/Agent User-Agent from hosts with no JVM workload
zeek-cut id.orig_h user_agent host < http.log 2>/dev/null | grep -i 'Java/Agent' | sort | uniq -c | sort -rn

# DNS: resolution of the pool host
grep -i 'unable.download' dns.log 2>/dev/null
```

## Act with Knowledge

- **Confirmed malicious:** `Java/Agent` egress or `unable[.]download` resolution from a host/account with no legitimate JVM app. Correlate the source host back to H1/H2; block the pool at egress and rotate any credentials the host could reach.
- **Benign baseline:** genuine Java agents/monitoring can emit `Java/Agent`; maintain an allowlist of JVM app hosts so the anomaly is the *unexpected* emitter.
- **Caveat (indicator decay):** LAN-pool mode uses hardcoded IPs that bypass DNS entirely; absence of `unable[.]download` in DNS does not clear a host - fall back to H2 host-side checks. Re-validate the pool host before treating it as currently live (feed stamps first_seen/last_seen).
