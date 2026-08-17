# PEAK hunt H1 - Browser shortcut integrity across the estate

## Prepare

**Hypothesis.** If the PATCHCORD cluster reached any endpoint in our estate, then at least one browser `.lnk` on that host now
points at a binary that is not a browser, and the original shortcut survives beside it with a `.backup` suffix. The persistence
is per-user and file-based, so it exists whether or not the implant is currently beaconing and whether or not the C2 domains
still resolve.

**Why this first.** The hijack is the one artefact common to all three implants in the cluster: PATCHCORD rewrites shortcuts
through `IShellLinkW` / `IPersistFile`, SHEETCORD generates a `temp_update.vbs` to do the same across six browsers, and the
HACKERAI C2 Agent reimplements the idea again. Domains rotate every few weeks; a rewritten shortcut does not.

**Scope.** Every Windows endpoint with an interactive user profile. Five shortcut locations per user, as enumerated by the
implant: Desktop (user and public), Start Menu, Quick Launch, and the Taskbar pinned folder
`%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`.

**Data quality check first.** Confirm your EDR actually records `.lnk` writes. Many deployments exclude shortcut files as noise.
If shortcut writes are not in telemetry, the live-query sweep below is the hunt and the telemetry gap is a finding in itself.

**Known-good baseline.** Resolve every browser shortcut on a freshly imaged host of each build. Anything whose target is not
under `Program Files`, `Program Files (x86)` or the vendor's per-user install path is a candidate.

## Execute

```powershell
# Author: Jarmi
# Resolve every browser shortcut for the current user and flag targets that are not the browser itself.
$shell = New-Object -ComObject WScript.Shell
$roots = @(
  [Environment]::GetFolderPath('Desktop'),
  [Environment]::GetFolderPath('CommonDesktopDirectory'),
  (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
  (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch'),
  (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
)
$browsers = 'chrome','msedge','firefox','brave','opera','vivaldi'
foreach ($root in $roots) {
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem -Path $root -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $lnk = $shell.CreateShortcut($_.FullName)
    $isBrowserName = $browsers | Where-Object { $_ -and $lnk.FullName -match $_ -or $lnk.TargetPath -match $_ }
    if ($isBrowserName) {
      [pscustomobject]@{
        Shortcut   = $_.FullName
        Target     = $lnk.TargetPath
        Arguments  = $lnk.Arguments
        WorkingDir = $lnk.WorkingDirectory
        Suspicious = ($lnk.TargetPath -notmatch 'Program Files') -or ($lnk.Arguments -match '\.exe')
      }
    }
  } | Where-Object Suspicious
}
```

```powershell
# Author: Jarmi
# The residue the hijack leaves behind: original shortcuts copied with a .backup suffix, and the SHEETCORD helper scripts.
Get-ChildItem -Path $env:APPDATA, $env:LOCALAPPDATA, "$env:PUBLIC", ([Environment]::GetFolderPath('Desktop')) `
  -Include '*.lnk.backup','temp_update.vbs','SystemHelper.vbs' -Recurse -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc | Sort-Object CreationTimeUtc
```

```kql
// Fleet-wide version of the same question in Defender XDR.
DeviceFileEvents
| where Timestamp > ago(90d)
| where FileName endswith ".lnk.backup" or FileName in~ ("temp_update.vbs", "SystemHelper.vbs")
| summarize FirstSeen = min(Timestamp), Artifacts = make_set(FolderPath, 20), Writers = make_set(InitiatingProcessFileName, 8)
        by DeviceId, DeviceName
| sort by FirstSeen asc
```

## Act

**A shortcut whose target is not a browser** is a confirmed hijack. Preserve the `.lnk`, the `.lnk.backup` and the target binary
before restoring anything - the shortcut argument string records the original browser path and is useful for timeline work.

**Only `.backup` files, no rewritten shortcut** means someone ran the `restore` tasking opcode, which reverts the hijack per
browser. Treat this as evidence of an operator interacting with the host, not as evidence the host is clean.

**Nothing found but shortcut telemetry is missing** is a gap, not an all-clear. Record the coverage deficiency, get `.lnk` writes
into telemetry, and re-run.

## Knowledge

Record the resolved-target baseline per build image so the next run is a diff instead of a full sweep. Feed confirmed hijack
paths back into the file_event Sigma rule in this folder. Note which browsers are actually deployed in your estate - the Go
implant extends the target list to Brave, Opera and Vivaldi, and an estate that only baselines the big three will miss those.
