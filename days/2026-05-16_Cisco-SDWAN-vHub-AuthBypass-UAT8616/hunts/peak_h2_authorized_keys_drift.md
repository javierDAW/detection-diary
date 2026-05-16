# PEAK Hunt H2 — Authorized-keys drift on `vmanage-admin` across the SD-WAN fleet

## Hypothesis (H2)

An attacker that obtained authenticated-peer status against a Cisco Catalyst SD-WAN
Controller has used the `MSG_VMANAGE_TO_PEER` (msg_type=14) primitive to append an
attacker-controlled public key into `/home/vmanage-admin/.ssh/authorized_keys`. Because
the file is opened in append mode by `vbond_proc_vmanage_to_peer()`, the legitimate keys
remain in place and the drift is silent. A snapshot of the authorized_keys file at known
clean state, compared with current state, will reveal any unauthorized key entry.

## Why this discriminates

`vmanage-admin` is an internal service account. Its `authorized_keys` file is typically
managed by Cisco automation and changes rarely. Drift between a known-clean snapshot and
the current state is high-signal. The append-mode semantics of the exploit prevent the
attacker from removing existing keys, so the drift is purely additive.

## Expected benign vs malicious

- **Expected benign:** drift caused by a documented platform upgrade or a change-managed
  re-key operation. Correlatable with a change ticket and Cisco automation logs.
- **Expected malicious:** an extra public key whose fingerprint does not match any in the
  organization's key inventory; addition not correlated with any change ticket; addition
  timestamped within minutes of a `peer-type:vhub` peering event.

## Queries

Baseline collection (run once on each controller, store the result in your CMDB or asset
inventory):

```bash
ssh admin@<sdwan-controller> "sudo cat /home/vmanage-admin/.ssh/authorized_keys" \
  | sha256sum > sdwan_authkeys_<hostname>_baseline.sha256
```

Periodic drift check:

```bash
for HOST in $SDWAN_CONTROLLERS; do
  CURRENT=$(ssh admin@$HOST "sudo cat /home/vmanage-admin/.ssh/authorized_keys" | sha256sum | awk '{print $1}')
  BASELINE=$(awk '{print $1}' sdwan_authkeys_${HOST}_baseline.sha256)
  if [ "$CURRENT" != "$BASELINE" ]; then
    echo ">>> DRIFT on $HOST: $CURRENT vs baseline $BASELINE"
  fi
done
```

KQL — if the controller is forwarding file integrity events (osquery / auditd-via-syslog):

```kql
Syslog
| where SyslogMessage has "/home/vmanage-admin/.ssh/authorized_keys"
| where SyslogMessage has_any ("WRITE","APPEND","MODIFY","open(O_APPEND)")
| project TimeGenerated, Computer, SyslogMessage
```

## Action on match

1. Capture the current `authorized_keys` content with `sudo cat` and snapshot the file's
   mtime / ctime / size.
2. Compute the fingerprint of every key entry and cross-reference against the org's
   inventory. Any unknown fingerprint is to be treated as adversary-controlled until proven
   otherwise.
3. Pull the syslog window 30 minutes before and after the file's mtime — look for
   `peer-type:vhub` peering events.
4. Containment: rotate the legitimate `vmanage-admin` keys, restrict NETCONF TCP/830 ingress
   to the orchestrator subnet only, patch to the fixed release.

## References

- https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW
