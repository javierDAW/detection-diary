# PEAK hunt H2 - File infector and removable-media artifacts

## Prepare

**Hypothesis.** If Sality is on a host, it has been rewriting legitimate executables and copying itself to removable and shared
drives, so there are signed binaries whose signature no longer validates, unexplained modification of many executables in a short
window, and `autorun.inf` files at the root of non-system drives. The disruption removed the botnet's tasking, not the infection:
CrowdStrike states the malware remains active on victims and should be removed.

**Why second.** The sinkhole signal in H1 needs egress telemetry; these artifacts live on the host, so they find the machines H1 cannot
see, including ones that are offline or behind unlogged egress.

**Honest limit.** The detailed host behaviour in public sources comes from the 2011 Symantec analysis: infection of `.exe` and `.scr`
files with an entry-point obscuring polymorphic stub, `autorun.inf` on drive roots, deletion of SafeBoot keys, and a kernel driver
service named `amsint32`. The 2026 CrowdStrike report does not republish these behaviours, so treat each as a legacy lead, not a
confirmed 2026 indicator.

**Data quality check first.** Confirm EDR records file modification of executables outside installer processes, and that you can
validate Authenticode signatures at scale (Defender, or a scripted sweep).

## Execute

```powershell
# Author: Jarmi
# Signed executables whose signature no longer validates: a file infector breaks the signature of anything it modifies.
Get-ChildItem -Path "$env:ProgramFiles","${env:ProgramFiles(x86)}","$env:SystemRoot\System32" -Include *.exe,*.scr -Recurse -ErrorAction SilentlyContinue |
  ForEach-Object { $s = Get-AuthenticodeSignature $_.FullName
    if ($s.Status -in 'HashMismatch','NotTrusted') { [pscustomobject]@{ Path=$_.FullName; Status=$s.Status; Modified=$_.LastWriteTimeUtc } } } |
  Sort-Object Modified -Descending | Select-Object -First 100
```

```powershell
# Author: Jarmi
# Drive roots with autorun.inf and the copy it points at (removable and network drives).
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne 'C' } | ForEach-Object {
  $f = Join-Path $_.Root 'autorun.inf'
  if (Test-Path $f -Force) { [pscustomobject]@{ Drive=$_.Name; File=$f; Content=(Get-Content $f -ErrorAction SilentlyContinue | Select-Object -First 6) -join ' | ' } } }
```

```kql
// Many executables modified in a short window by a process that is not an installer or updater.
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileModified" and FileName endswith_cs ".exe"
| where InitiatingProcessFileName !in~ ("msiexec.exe","TrustedInstaller.exe","setup.exe","<add_known_updaters>")
| summarize Files = dcount(FolderPath), Window = max(Timestamp) - min(Timestamp), Sample = make_set(FolderPath, 5) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 30m)
| where Files >= 15
| sort by Files desc
```

## Act

**An executable with `HashMismatch` that the vendor did not patch** is a candidate infected file: preserve it, hash it, and scan with the
YARA rules in this folder; compare it against a clean copy from the vendor. Restore from clean media, not by deleting the infector alone,
because the infector is inside the legitimate file.

**An `autorun.inf` on a removable or network drive** means that drive carries a copy and can reinfect other hosts; quarantine the drive.

**A service named `amsint32`** or a SafeBoot deletion is a legacy-variant lead: image the host before anything else.

**Nothing found** is plausible on a modern, application-allowlisted estate; record which segments allow unsigned execution because
those are where a file infector survives.

## Knowledge

Keep a baseline of signature-validation failures per software image so that a vendor's own breakage does not hide an infection, and
record whether USB autorun and network-share executable execution are blocked by policy.
