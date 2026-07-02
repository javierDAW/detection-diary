# PEAK Hunt H1 — SEO-poisoned MSI to BumbleBee sideload to DGA C2

**Hypothesis (P).** On at least one host, an installer (MSI/EXE) executed from a user download or temp path is followed within minutes by the legitimate `consent.exe` loading a `msimg32.dll` from a non-System32 path, and then by outbound HTTPS to a newly-seen `.org` domain. This is the BumbleBee delivery-to-C2 sequence.

**Why it works.** The sideload runs at execution time, before any hands-on-keyboard activity, and a signed system binary loading a system-named DLL from `%TEMP%`/`%AppData%` is hash-independent and low-noise. Chaining it to a fresh `.org` lookup separates the loader from benign application launches.

**Enrich (E).** Join image-load telemetry (Sysmon EID 7 / `DeviceImageLoadEvents`) with process creation (the parent MSI) and DNS/network telemetry on the same host and short time window.

```kql
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "consent.exe"
| where FileName =~ "msimg32.dll"
| where FolderPath !has @"\Windows\System32\" and FolderPath !has @"\Windows\SysWOW64\" and FolderPath !has @"\WinSxS\"
| project SideloadTime=Timestamp, DeviceName, InitiatingProcessFolderPath, FolderPath
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl endswith ".org"
    | project NetTime=Timestamp, DeviceName, RemoteUrl, RemoteIP
  ) on DeviceName
| where NetTime between (SideloadTime .. (SideloadTime + 1h))
```

**Analyze (A).** A host with the sideload plus a fresh `.org` beacon inside an hour is a strong lead. Filter the `.org` set against known-good software update domains; the DGA labels are high-entropy 14-character strings.

**Knowledge (K).** Baseline any legitimate apps that ship their own `msimg32.dll`. Promote to the `sigma/bumblebee_consent_msimg32_sideload.yml` alert once the benign set is documented; feed confirmed DGA domains to the `suricata/` DNS rules.
