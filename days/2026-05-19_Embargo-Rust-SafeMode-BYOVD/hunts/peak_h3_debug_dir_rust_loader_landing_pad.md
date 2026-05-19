# PEAK H3 — `C:\Windows\Debug\` as Rust-loader landing pad (Embargo MDeployer)

## Hypothesis

Embargo MDeployer uses `C:\Windows\Debug\` as its canonical staging area:
`a.cache` (RC4-encrypted ransomware payload), `b.cache` (RC4-encrypted
MS4Killer), `pay.exe` (decrypted ransomware), `dtest.dll` (MDeployer DLL),
`stop.exe` (flow-control sentinel), `fail.txt` (stage log). None of these
filenames are produced by legitimate Windows tooling in this directory; the
combination is a high-confidence Embargo indicator.

## Why this discriminates

`C:\Windows\Debug\` legitimately holds Microsoft trace files (mostly `*.log`
from Bluetooth-Audio-Capture, WIA, NetSetup) and is never used by Windows
itself for executables, DLLs, or files with the `.cache` extension. Any
write to this directory of a file matching the MDeployer asset list is
discriminating on its own; the burst pattern (multiple Embargo filenames
within minutes) is decisive.

## Expected benign vs malicious

| Signal | Benign | Malicious |
|---|---|---|
| Write to `C:\Windows\Debug\` | `*.log` from Microsoft built-in tracing | `a.cache`, `b.cache`, `pay.exe`, `dtest.dll`, `stop.exe`, `fail.txt` |
| `.cache` extension in this directory | None | MDeployer payload |
| `.exe` in this directory | None | MDeployer-decrypted Embargo ransomware |
| `.dll` in this directory | None | MDeployer DLL variant (`dtest.dll`) |

## Action on match

1. EDR isolate the host immediately.
2. Acquire `C:\Windows\Debug\` directory contents before the MDeployer
   cleanup routine fires.
3. Inspect `fail.txt` for stage prefix history — it reveals which stage
   succeeded or failed and what the operator tried.
4. Hash the dropped payloads against the ESET-published SHA1 list to
   confirm Embargo lineage.
5. Pivot to H1 (Safe Mode reboot) and H2 (BYOVD) on the same host.

## Queries

### Defender XDR — burst of MDeployer asset writes within 10 minutes

```kql
let WindowMin = 10m;
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"C:\Windows\Debug"
| where FileName in~ ("a.cache", "b.cache", "fail.txt", "stop.exe", "pay.exe", "dtest.dll")
| summarize Files = make_set(FileName), FileCount = dcount(FileName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceId, DeviceName, bin(Timestamp, WindowMin)
| where FileCount >= 2
| order by FirstSeen desc
```

### Velociraptor / KAPE — directory snapshot

```text
Glob C:\Windows\Debug\*
Hash a.cache, b.cache, pay.exe, dtest.dll, praxisbackup.exe
Compare against known Embargo SHA1 anchors:
  - A1B98B1FBF69AF79E5A3F27AA6256417488CC117 (dtest.dll)
  - F0A25529B0D0AABCE9D72BA46AAF1C78C5B48C31 (fxc.exe)
  - 2BA9BF8DD320990119F42F6F68846D8FB14194D6 (fdasvc.exe)
  - 888F27DD2269119CF9524474A6A0B559D0D201A1 (praxisbackup.exe)
  - 8A85C1399A0E404C8285A723C4214942A45BBFF9 (pay.exe)
```

### Cross-host fleet sweep (PowerShell, run remotely)

```powershell
Get-ChildItem 'C:\Windows\Debug\' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in 'a.cache','b.cache','pay.exe','dtest.dll','stop.exe','fail.txt' } |
    Select-Object FullName, Length, CreationTime, LastWriteTime
```

## False positives to triage

- Microsoft trace files (`*.log`) in this directory are expected — they do
  not match the filename anchors of this hunt.
- Bespoke enterprise tooling that uses `C:\Windows\Debug\` as a working
  directory is unusual; if present, document and allowlist by filename.
