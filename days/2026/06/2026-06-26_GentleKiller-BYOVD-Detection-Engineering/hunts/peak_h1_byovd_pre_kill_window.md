# PEAK Hunt H1 — BYOVD Pre-Kill Window: Driver Service Creation Before EDR Goes Silent

## Hunt Type
Hypothesis-driven / frequency

## Hypothesis
An attacker using GentleKiller or any BYOVD EDR-killer will install a vulnerable kernel
driver as a Windows service in the seconds-to-minutes BEFORE security product processes
disappear from telemetry. If we correlate driver service creation from non-standard paths
with the subsequent loss of EDR heartbeat from the same host, we can identify the pre-kill
window and respond before encryption begins.

## Rationale
ESET confirmed GentleKiller installs each driver variant (eb.sys, nseckrnl.sys, vgk.sys,
stpm_old/new.sys, dmx.sys, 360netmon_wfp.sys, IMFForceDelete, G11.sys/PoisonX) as a
Windows service via sc.exe or the Service Control Manager API (T1543.003) BEFORE using
DeviceIoControl to reach the kernel and terminate security processes. This service creation
step is the last moment when full telemetry is available. Detection must fire here.

## Data Sources
- Defender XDR: DeviceRegistryEvents (service ImagePath writes)
- Sysmon EID 6: RawAccessRead / ImageLoad for driver .sys
- Windows Event Log: System 7045 (New Service Installed), 7036 (Service started)
- EDR heartbeat gaps: host stops sending telemetry → treat as compromise indicator

## Hunt Query (KQL)

```kql
// Step 1: Find driver services created from non-standard paths in last 7 days
let SuspiciousDriverServices = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"HKLM\SYSTEM\CurrentControlSet\Services"
| where RegistryValueName == "ImagePath"
| where RegistryValueData endswith ".sys"
| where RegistryValueData has_any (
    @"\Temp\", @"\AppData\", @"\Users\Public\",
    @"\ProgramData\", @"\Downloads\"
)
| project DeviceName, ServiceInstallTime = Timestamp,
    DriverPath = RegistryValueData,
    InitiatingProcessCommandLine;

// Step 2: Find hosts that lost EDR heartbeat within 10 minutes after driver install
let EDRSilence = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessTerminated"
| where FileName in~ (
    "MsMpEng.exe","CSFalconService.exe","SentinelAgent.exe",
    "SophosHealth.exe","ekrn.exe","bdagent.exe","HuntressAgent.exe"
)
| summarize FirstKill = min(Timestamp), KilledProcesses = make_set(FileName, 10)
    by DeviceName;

// Step 3: Correlate — driver install within 10 minutes before EDR kill
SuspiciousDriverServices
| join kind=inner EDRSilence on DeviceName
| where FirstKill > ServiceInstallTime and
        FirstKill < datetime_add('minute', 10, ServiceInstallTime)
| project
    DeviceName,
    ServiceInstallTime,
    DriverPath,
    EDRKillTime = FirstKill,
    GapSeconds = datetime_diff('second', FirstKill, ServiceInstallTime),
    KilledProcesses
| order by GapSeconds asc
```

## Expected Output
Hosts where a kernel driver was installed as a service from a temp/data path and then
security processes died within 10 minutes. Any match warrants immediate isolation.

## True Positive Indicators
- Driver in %TEMP% or %PROGRAMDATA% (never legitimate for signed security drivers)
- Service type = kernel (0x1 in registry Start/Type)
- Security processes terminate 30–300 seconds after driver install
- GentlemenCollection directory present on same host

## False Positive Mitigations
- Exclude known software deployers (endpoint management, security tooling with signed paths)
- Require the .sys file to be unsigned or from an unknown publisher (use DeviceImageLoadEvents SHA-1 lookup)

## Response Action
1. Isolate host from network immediately (do not wait for further confirmation)
2. Collect volatile memory before any reboot
3. Pull DeviceRegistryEvents around the ServiceInstallTime window
4. Hash the driver file and compare to ESET IOC list (SHA-1 table in README)
