# PEAK H1 — AI-paced reconnaissance pivot from IT into OT-adjacent assets

## Hypothesis

A single endpoint inside the corporate IT network executes a Python launcher that, within a window of less than one hour, performs broad internal enumeration, fetches public vendor documentation for an OT/IIoT management product, generates a tailored credential list, and emits a burst of HTTP POST requests against an OT/SCADA management web endpoint. This time-compressed sequence is the operational signature of an LLM-assisted operator. It is what Dragos and Gambit Security observed during the May 2026 intrusion against the Monterrey water utility (SADM), where Anthropic Claude identified a vNode SCADA gateway and ran two automated password-spray rounds against it.

## Why this discriminates

Manual operators rarely complete the pivot from broad enumeration to a credential-aware password spray inside an hour. They typically split discovery, vendor research, credential-list construction and active testing across multiple sessions and often across days. The LLM compresses the loop. Detection therefore relies less on individual high-fidelity events and more on the *temporal density* of low-individual-fidelity events on a single host.

## Data sources

- Defender XDR — `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`.
- Sentinel — `SecurityEvent` (4625 logon failures), `CommonSecurityLog` (firewall flow), `Syslog` (web mgmt auth logs).
- Zeek — `conn.log`, `http.log` at the IT-OT seam.
- Edge proxy / SWG — outbound TLS to LLM API endpoints.

## Query — primary, Defender XDR

```kql
let Window = 60m;
let SuspiciousProcs = dynamic(['python.exe','python3','pythonw.exe','py.exe',
                                'powershell.exe','pwsh.exe']);
let OtPorts = dynamic([8043,8088,8090,8443,9090,9443,
                       102,502,4840,44818,47808]);
let recon =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (SuspiciousProcs)
    | where ipv4_is_private(RemoteIP)
    | summarize InternalTargets = dcount(RemoteIP),
                InternalPorts = dcount(RemotePort)
        by DeviceId, DeviceName, InitiatingProcessId, bin(Timestamp, Window)
    | where InternalTargets >= 30 and InternalPorts >= 4;
let post_burst =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (SuspiciousProcs)
    | where RemotePort in (OtPorts)
    | summarize OtAttempts = count(),
                OtTargets = dcount(RemoteIP)
        by DeviceId, InitiatingProcessId, bin(Timestamp, Window)
    | where OtAttempts >= 15;
recon
| join kind=inner post_burst on DeviceId, InitiatingProcessId, Timestamp
| order by Timestamp desc
```

## Expected benign vs malicious

- **Benign:** authorised vulnerability scanners and red-team engagements. These hosts should be on a known list and ideally tagged in DeviceInfo.
- **Benign:** backup tools and inventory scanners that reach OT mgmt ports during scheduled maintenance windows.
- **Malicious:** workstation-class hosts with a *user* account context, a Python launcher with long command lines, and time-compressed transitions from broad enumeration to a focused credential-spray burst.

## Action on match

1. Trigger an alert at severity high; include the device, process tree and the join key.
2. Page the on-call IR analyst with the investigation runbook from `incident response playbook` in the day's README.
3. Open a forensic memory acquisition on the host before isolation.
4. Cross-check the user account against any cross-tenant credential reuse, because the LLM operator pattern recombines harvested credentials.

## Tuning

- Lower `InternalTargets` or `OtAttempts` for environments with a small number of OT hosts.
- Add `DeviceCategory == "Workstation"` to suppress matches on sanctioned scanning hosts.
- Whitelist by DeviceTags (`scanner`, `red-team`, `pentest-host`).

## References

- [AI in the Breach: How an Adversary Leveraged AI to Target a Water Utility's OT — Dragos blog, 6-May-2026](https://www.dragos.com/blog/ai-assisted-ics-attack-water-utility)
- [Dragos details AI-assisted intrusion targeting Mexican water utility — Industrial Cyber, 8-May-2026](https://industrialcyber.co/reports/dragos-details-ai-assisted-intrusion-targeting-mexican-water-utility-as-claude-openai-models-used-to-pursue-ot-access/)
- [PEAK Threat Hunting Framework — SURGe](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
