# PEAK H2 — Three-cadence automation hunt (15 s WiFi + 23 s mouse + 67 s WMI)

## Hypothesis

If a JWrapper-packaged SimpleHelp RAT is running on a Windows host with no operator at the keyboard, then three deterministic polling loops are visible in process-creation telemetry — `netsh wlan show interfaces` at a ~15-second cadence, `elev_win.exe --mouselocation` at a ~23-second cadence, and a four-query `SecurityCenter2` WMI batch plus `netsh advfirewall show all State` at a ~67-second cadence — producing approximately 986 process-creation events per hour from one logical parent process tree.

## Why this discriminates

Legitimate user activity on a Windows desktop produces non-deterministic inter-arrival times for shell tools. A deterministic cadence — and especially three deterministic cadences from the same parent process tree — is the textbook signature of automated polling. Securonix observed this pattern in their one-hour controlled dynamic analysis with no human input, and the equal per-hour counts across the four `SecurityCenter2` queries (54 each) prove a single batched timer rather than independent triggers.

## Expected benign

- Some endpoint-management tooling runs WMI `SecurityCenter2` enumeration to report on installed AV — typically once every several minutes, not every 67 seconds, and not in parallel with `netsh wlan` and a mouse-position poll from the same parent.
- Wi-Fi adapter polling at 15-second cadence is plausible for some VPN clients on flaky networks, but a VPN client does not also fire a mouse-position helper named `elev_win.exe`.

## Expected malicious

- `netsh wlan show interfaces` invoked ~233 times in a one-hour window (cadence ≈ 15.4 s) from a parent process under `C:\ProgramData\JWrapper-Remote Access\`.
- `elev_win.exe --mouselocation` invoked ~157 times in the same hour (cadence ≈ 22.9 s).
- WMI `root\SecurityCenter2` `AntiVirusProduct`, `AntiSpywareProduct`, `FirewallProduct` and `netsh advfirewall show all State` invoked ~54 times each in the same hour (cadence ≈ 67 s).
- All three loops share the same logical parent process tree rooted at `Remote Access.exe` or `customer.jar` under JWrapper.

## Actions

1. Pull a 4-hour `DeviceProcessEvents` window per host. Group by `InitiatingProcessFileName` and by the regular expression of `ProcessCommandLine` matching the three commands above.
2. For each candidate host, compute the standard deviation of inter-arrival times for each of the three command families. Deterministic timers produce standard deviations in the low-hundreds-of-milliseconds range; legitimate user activity does not.
3. Cross-correlate to confirm that all three families fire with overlapping windows — if all three share a parent process and are firing concurrently, it is almost certainly the JWrapper RAT.
4. Pivot to `DeviceFileEvents` to confirm presence of `sgalive` watchdog file at `C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\sgalive` with regular write events.

## Telemetry

- Defender XDR: `DeviceProcessEvents` (with `ProcessCommandLine` enriched), `DeviceFileEvents`.
- Sysmon: EID 1 (process creation) with full command line.
- Splunk-equivalent windowing: 4-hour rolling window with inter-arrival statistics keyed on parent process.
