# PEAK Hunt H2 - Mass .encrypted Rename From a Datastore

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If the ByteToCrypt encryptor walked a datastore, then a single process renamed many files to `*.encrypted` via `*.tmp` intermediates under a VM datastore or user tree, single-threaded, dropping a plaintext `note` file per directory.

## Prepare

- **ATT&CK:** T1486 (Data Encrypted for Impact), T1083 (File and Directory Discovery).
- **Data sources:** Linux `file_event`/auditd rename+create, EDR DeviceFileEvents, storage/datastore access logs.
- **Scope:** hypervisor/datastore hosts first (the binary is not ESXi-aware; it only reaches VMs when run from a datastore).

## Execute

```bash
# Encrypted-file footprint and orphan intermediates (recovery candidates)
find /vmfs/volumes /srv /home /var/lib -name '*.encrypted' 2>/dev/null | head
find /vmfs/volumes /srv /home /var/lib -name '*.tmp' -newermt '-1 day' 2>/dev/null | head
find /vmfs/volumes /srv /home /var/lib -type f -name 'note' 2>/dev/null | head

# Confirm the ByteToCrypt header shape on a suspect file (00 02 length + 512B wrapped key)
for f in $(find . -name '*.encrypted' 2>/dev/null | head -3); do echo "$f"; xxd -l 4 "$f"; done

# Identify the encrypting process and its working directory
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  cwd=$(readlink /proc/$p/cwd 2>/dev/null)
  echo "$p $(cat /proc/$p/comm 2>/dev/null) cwd=$cwd"
done | grep -Ei 'vmfs|datastore|volumes'
```

```kql
DeviceFileEvents
| where FileName endswith ".encrypted" or FileName endswith ".tmp"
| summarize Encrypted = dcountif(FileName, FileName endswith ".encrypted"),
    Tmp = dcountif(FileName, FileName endswith ".tmp")
    by DeviceId, InitiatingProcessId, InitiatingProcessFileName, bin(Timestamp, 5m)
| where Encrypted >= 25
```

## Act with Knowledge

- **Confirmed malicious:** one process producing many `.encrypted` files with `.tmp` siblings and a per-directory `note`, header starting `00 02` then a 512-byte block.
- **Benign baseline:** backup tools that append `.encrypted` produce steady, low-rate output from a known binary; the ransomware is a fast single-threaded burst from an unexpected CWD.
- **Feed forward:** the CWD confirms datastore blast radius; orphan `.tmp` and surviving plaintext feed the recovery path; the process feeds H1 (anti-forensics) and H3 (who staged it).
