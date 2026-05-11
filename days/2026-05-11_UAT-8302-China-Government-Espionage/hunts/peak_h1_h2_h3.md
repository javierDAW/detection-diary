# PEAK Hunting — UAT-8302 China-nexus government espionage

Author: Jarmi
Date:   2026-05-11
Reference: https://blog.talosintelligence.com/uat-8302/

Three Prepare-Execute-Act-Knowledge (PEAK) hunts derived from the Cisco
Talos UAT-8302 disclosure. Each hunt names the hypothesis, the discriminating
signal, what should be benign in baseline, and the action on match.

---

## H1 — Side-load triad living in `ProgramData\Microsoft\Microsoft\`

**Hypothesis.** Any process executing from
`C:\ProgramData\Microsoft\Microsoft\<anything>.exe` that loads a non-System32
DLL and opens a TLS socket to `graph.microsoft.com` is UAT-8302 NetDraft.

**Why this discriminates.** The path with the double `Microsoft\Microsoft`
segment is not used by any legitimate Microsoft installer; it is a
camouflage path specific to NetDraft's persistence drop. Combined with a
DLL load outside System32 and a Graph API egress, the false-positive
surface collapses to near zero in managed government endpoints.

**Expected benign vs malicious.**
- Benign: none. The path itself is a hard anchor.
- Malicious: NetDraft loader running `Yandex.exe -r -p:test.ini -s:12`
  or `Appunion.exe` beaconing through Graph.

**Action on match.** Isolate host, capture RAM, escalate to APT IR.

```kql
DeviceProcessEvents
| where FolderPath has "\\ProgramData\\Microsoft\\Microsoft\\"
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteUrl has_any ("graph.microsoft.com","login.microsoftonline.com")
  ) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, FolderPath, FileName, RemoteUrl, RemoteIP
```

---

## H2 — AD Connect dump tooling fingerprint

**Hypothesis.** Execution of `adconnectdump.py`, or `python.exe` with a
command line containing `aadconnect`, `adconnect`, or `ADSync` (excluding
the legitimate ADSync service host), on a host that is not the formal
AAD Connect appliance is hybrid-identity credential exfiltration.

**Why this discriminates.** The Entra Connect appliance is a dedicated
tier-0 box; nobody else should be touching its sync secrets. Any other
host running this tooling is, by construction, malicious or a
sanctioned red-team engagement.

**Expected benign vs malicious.**
- Benign: registered pentest engagement; sanctioned tier-0 audit.
- Malicious: UAT-8302 dumping the AAD Connect credential set as
  pre-staging for cross-tenant pivoting and for revoking the victim's
  ability to detect via cloud telemetry.

**Action on match.** Escalate to tier-0 IR, suspend the synced service
account, plan triple-tap krbtgt rotation, audit Entra ID app
registrations and OAuth grants in the last 30 days.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe","python3.exe")
| where InitiatingProcessCommandLine has_any
        ("adconnectdump.py","aadconnect","adconnect","ADSync")
| where DeviceName !in (<add_known_aadconnect_hosts>)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          ProcessCommandLine
```

---

## H3 — GitHub or GameSpot dead-drop resolver C2 channel

**Hypothesis.** A host that performs an HTTPS GET against a public
GitHub raw file or a GameSpot user profile, and within the next five
minutes opens a connection to a previously unseen public IP, is
performing CloudSorcerer v3-class dead-drop resolution.

**Why this discriminates.** The "pull a public blob, then connect to
the destination it encodes" sequence is highly structural and
infrequent in benign traffic. Developers pulling code from GitHub do
not subsequently connect to a different public IP derived from that
fetch; they connect to package mirrors that are well known and that
the join in the query excludes.

**Expected benign vs malicious.**
- Benign: developer fetching a GitHub asset then resolving a package
  mirror or CDN endpoint (filtered by mirror domain allowlist).
- Malicious: CloudSorcerer v3 reading the encoded C2 URL or OAuth
  token from a public blob and then beaconing to the encoded
  destination.

**Action on match.** Capture the blob, decode it, identify the
embedded C2 URL or token, revoke the token if it belongs to a
controlled tenant, network-quarantine the host.

```kql
let deaddrop = DeviceNetworkEvents
  | where Timestamp > ago(24h)
  | where RemoteUrl has_any ("raw.githubusercontent.com","github.com","gamespot.com");
let followup = DeviceNetworkEvents
  | where Timestamp > ago(24h)
  | where RemoteIPType == "Public"
  | where RemoteUrl !has "github" and RemoteUrl !has "gamespot";
deaddrop
| join kind=inner followup on DeviceId, InitiatingProcessId
| where followup.Timestamp between (deaddrop.Timestamp .. (deaddrop.Timestamp + 5m))
| summarize first_seen=min(followup.Timestamp), derived=make_set(followup.RemoteIP, 50)
            by DeviceName, InitiatingProcessFileName
| where array_length(derived) >= 1
```
