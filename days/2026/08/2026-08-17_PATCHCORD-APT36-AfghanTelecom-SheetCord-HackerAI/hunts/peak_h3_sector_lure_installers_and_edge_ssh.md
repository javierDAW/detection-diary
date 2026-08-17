# PEAK hunt H3 - Sector-themed installers and the network-level access path

## Prepare

**Hypothesis.** If we are inside this campaign's target set - telecom, government, defence or energy in South Asia, or any
organisation whose staff would plausibly install a branded internal tool - then either (a) an Inno Setup installer impersonating
a sector-specific application executed on an endpoint in the last nine months, or (b) our internet-facing OpenSSH was probed by
the same operator, who staged `CVE-2024-6387` (regreSSHion) tooling and a password list on the exposed server.

**Why both halves.** The endpoint half and the network half are the two documented entry paths for this operator. Acronis
assessed the SSH exploit tooling as an attempt to reach telecom infrastructure at the service level rather than only through
employee endpoints, so an endpoint-only hunt would confirm nothing about the perimeter.

**Scope.** Twelve months of process-creation telemetry (the earliest cluster domain dates to September 2025), plus SSH
authentication and connection logs for every internet-facing host, plus web proxy logs for downloads of `.exe`, `.msi` and `.zip`
from newly registered domains.

**Data quality check first.** Confirm SSH logs are centralised and that `LogLevel` is at least `VERBOSE` on edge hosts - the
default `INFO` will not record the failed pre-auth handshakes that regreSSHion exploitation produces in volume.

**Known-good baseline.** List the internal applications your organisation actually distributes and how they are packaged. Any
Inno Setup installer whose `AppPublisher` names your organisation but which did not come from your software distribution channel
is the finding.

## Execute

```kql
// Inno Setup droppers with sector-branded metadata, and the known cluster hashes.
let cluster_hashes = dynamic([
  "cf7184c0dfe882dc6e3016f16e4ede32b75d7648f83d6f4f87eb6a703be7b8d6",
  "1774e15e8eb96eb89bc03cb4768fc0620e10c09c5f795297f36dcc2aa5d9dd94",
  "ea0934472121848b80455581d289ce4480b1e5cc05678c1b90ecfc465b5ec350",
  "5e17360d32e9b272bb7e1b97c8e4dca34622ec9ce08fd240fe2758cc3f67dc4a",
  "378484112b4e837d3850b5b0802fc509202c232bb124d6944a59fe66525ba668",
  "b56fab5a6834c51d85787e7c1177720dfba5a5823763f3fcf432196cd2a1bdf3",
  "2323b55ea743c813e48689318e8ed54ae838cf9e8a2adbfc2488ea8a36dd0126",
  "2eddfebb3f7419af27493a6a3bb601372cf6c494da8df62640cce7f830b4a73b",
  "d46ee94d6a27ff9f02cff6fb57780acac2833ce48c95e63042a6274e24a040bb",
  "50fc220347f9e281037e831c3755dc70a8ba7f663025aea35b301226918b016b",
  "0f4073d3c866bc3daf55b25f71250b96ec120db94a4f9cc8fe85b7c9f9d346b3",
  "959bbb09cd86ce3930406bf1cf32776ca477dfefe3fd63e90bf0017fccd90587",
  "74d347785dc47f8cda3876826cdd3fb3935ac55dc8e9e0c0f96d5ef4e00089a2"]);
DeviceProcessEvents
| where Timestamp > ago(365d)
| where SHA256 in~ (cluster_hashes)
    or FileName has_any ("TMS_AfghanTelecom", "AFTEL_VPN_Setup", "MDEB_Update_Setup",
                         "MOFA_Employee_Benefits", "nhpcfuelconservationservice", "JitsiMeet-Setup")
    or (ProcessCommandLine has "/VERYSILENT" and FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

```bash
# Author: Jarmi
# regreSSHion probing shape: a burst of connections that reach the auth stage and are cut at the LoginGraceTime boundary.
# Exploitation of CVE-2024-6387 needs thousands of attempts, so the volume is the signal.
grep -E 'Timeout before authentication|fatal: Timeout before authentication' /var/log/auth.log \
  | awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/) print $i}' \
  | sort | uniq -c | sort -rn | head -25
```

```bash
# Author: Jarmi
# Confirm the edge is not actually vulnerable before chasing noise, and check for post-exploitation local escalation tooling.
ssh -V 2>&1
dpkg -l openssh-server 2>/dev/null | tail -1 || rpm -q openssh-server 2>/dev/null
# PwnKit (CVE-2021-4034) was also staged by this operator - verify pkexec is patched or unprivileged.
ls -l /usr/bin/pkexec 2>/dev/null
pkexec --version 2>/dev/null
```

```bash
# Author: Jarmi
# Proxy-side: executable downloads from the cluster's domain set, refanged for grepping.
grep -Ei '(appstoore|afghantelecom|afghanistanupdates|caprispine|servicesindia|zala-aer|nicservice|nic-support|cdga\.site|cgda\.site)' \
  /var/log/proxy/access.log \
  | grep -Ei '\.(exe|msi|zip)(\?|$| )' \
  | awk '{print $1, $3, $7}' | sort | uniq -c | sort -rn
```

## Act

**An installer hit** means treat the endpoint as compromised regardless of whether the implant is still running: pull the Run
key values, the shortcut set, and the `%TEMP%` Inno Setup extraction directory, then work outward to whoever else received the
same lure. The lures are role-targeted (transport requests, VPN clients, employee benefits), so the recipient list tells you
what the operator believed our org chart looked like.

**SSH probing without an installer hit** is still actionable: it means the operator is working the perimeter path. Patch or
confirm OpenSSH is out of the vulnerable range, and pull a full authentication history for any account that succeeded from a
probing source.

**Neither** - record the negative with its scope so the next analyst does not repeat the twelve-month sweep, and keep the
sector-lure heuristic as a standing detection. The staging server held four archives that had never been distributed, so more
lures in this style are expected.

## Knowledge

The durable lesson to write down is the *shape*: a signed-looking Inno Setup installer whose publisher metadata names a real
organisation, distributed from a lookalike domain, carrying a small MSVC or Go payload. Record which of your internal
applications would be most credible to impersonate, and put those names on a domain-registration watch list.
