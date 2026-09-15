# PEAK hunt H2 - Host: the "C:\Windows \" directory, Run keys and Defender exclusions

## Prepare

**Hypothesis.** If a host ran one of the published samples, it holds a directory whose name is "Windows " with a trailing space
beside the real one, an HKCU Run value named `winappx`, `SMQDService`, `Default_SSH` or `MicDriver`, a PowerShell
`Add-MpPreference` exclusion for the staging folders, and folders under `C:\ProgramData` named `SMQDServicePackages`,
`ssh-cache-default`, `MicrosoftDistribution\sysmain` or `Drivers\MicDriver`.

**Why.** The advisory gives these as examples and says names may change, so they are a known-sample check, not a ceiling. They are
cheap to sweep and nearly free of false positives.

**Scope.** Every managed Windows endpoint of at-risk users, then a sample of the rest. Include removable-image and VDI templates:
a lure that was run once persists through the Run key at the next logon.

**Data quality check first.** Check that your EDR records registry value data and PowerShell command lines. Run-key detections on
value names alone are noisy.

## Execute

```powershell
# Author: Jarmi
# On a suspect host: the look-alike directory, the Run values and the staging folders.
Get-ChildItem 'C:\' -Force | Where-Object { $_.Name -like 'Windows *' } | Select-Object FullName, CreationTimeUtc
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object winappx, SMQDService, Default_SSH, MicDriver
Get-ChildItem 'C:\ProgramData' -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -in 'SMQDServicePackages','ssh-cache-default','MicrosoftDistribution','Drivers' } | Select-Object FullName, CreationTimeUtc
(Get-MpPreference).ExclusionPath
```

```cmd
:: Author: Jarmi
:: The advisory's own check, plus a listing of the directory with the space in its name.
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
dir /a "C:\Windows \"
```

```kql
// Defender XDR: the three host signals per device, as in kql/k1.
// Run k1_chosen_brick_persistence_and_defender_exclusions.kql and sort by SignalClasses.
```

## Act

**Any of the Run values with a staging path, or a process from `C:\Windows \`,** means the host executed the implant. Capture memory
and the files, then reinstall; the implant can download further malware and in at least one sample wipe the system, so do not try to clean
it in place.

**A Defender exclusion naming a staging folder** is enough to escalate even without the implant on disk, because the dropper adds
exclusions before it unpacks.

**No hits** mean no known sample ran under those names. The advisory says directories and value names may change; fall back to H1.
