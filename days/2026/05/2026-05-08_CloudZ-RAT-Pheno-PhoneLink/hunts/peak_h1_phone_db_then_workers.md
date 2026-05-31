# PEAK Hunt H1 — Phone Link SQLite read followed by hellohiall.workers.dev egress

## Hypothesis

A user-context process other than the Microsoft YourPhone UWP package opens or copies the Phone Link SQLite cache (`PhoneExperiences-*.db`) and within thirty minutes the same host beacons to a `*.hellohiall.workers.dev` URL or to the CloudZ backend IP `185.196.10.136`. This pairing is the dwell-time fingerprint of the Pheno plugin shipped with CloudZ — the file read corresponds to the OTP harvest step and the network leg corresponds to either configuration refresh or exfiltration.

## Why this discriminates

- The PhoneExperiences database is normally read only by `YourPhone.exe` and `PhoneExperienceHost.exe` from the UWP package directory `Microsoft.YourPhone_8wekyb3d8bbwe`. Any other process touching that file is anomalous on a stock Windows 11 machine.
- `*.hellohiall.workers.dev` is a Talos-published, attacker-controlled namespace. There is no legitimate business reason for an enterprise host to resolve or connect to it.
- The thirty-minute correlation window is short enough to keep noise low and long enough to absorb operator latency. CloudZ pulls Pheno on demand, so the loader process and the network process can differ; pivoting on `DeviceId` rather than process tree avoids that gap.

## Expected benign vs malicious

Benign paths to the same telemetry shape are:

- Endpoint backup agents (Code42, Druva, Veeam endpoint) snapshotting AppData on schedule. They have a stable parent path and a vendor signature.
- Antivirus on-access scans briefly opening the file.
- Forensic acquisition tooling during an active investigation.

Malicious paths look like:

- Process living under `%APPDATA%\<random>\` or `%LOCALAPPDATA%\<random>\` with a recent first-seen timestamp.
- Process with no Authenticode signature, or signed by a non-Microsoft CN that has no other footprint on the host.
- Beaconing process is the same image or a sibling spawned within minutes of the database read.

## Query

The detection-diary KQL `kql/cloudz_phone_db_to_workers_correlation.kql` is the production query for this hunt. It joins `DeviceFileEvents` and `DeviceNetworkEvents` on `DeviceId` and filters the time delta to thirty minutes.

## Action on match

1. Triage: pull the parent process tree of the file-event initiator. Look for an AppData-resident dropper, a scheduled task creation event in the prior twenty-four hours, and a fake-installer image name.
2. Containment: isolate the host via the EDR isolation channel. Do not reboot — the loader stages live in memory and a reboot loses evidence. Acquire a memory image first.
3. Identity: revoke active sessions and refresh tokens for the user across IdP, M365, banking and critical SaaS. Treat all SMS-based 2FA codes as potentially captured. Migrate the user to FIDO2 / passkey before re-enabling access.
4. Forensics: preserve `Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\PhoneExperiences-*.db`, the dropper, the loader, the scheduled task XML in `C:\Windows\System32\Tasks\`, prefetch entries, Amcache and ShimCache entries. Hash everything against the Talos IOC list before erasing.
5. Eradication: re-image the host. Do not attempt to clean — the dynamic IL emit layer plus a scheduled-task persistence plus possible browser-credential theft means a remnant is plausible.

## Hunt validation

Run this hunt on a baseline window before pushing to production. Verify the false-positive list against a typical week of data and confirm the time-delta join performs within the SIEM window budget. Document any allow-listed backup agent paths in the team runbook so future analysts do not re-derive them.
