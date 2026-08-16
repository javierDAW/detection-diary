# PEAK hunt H2 - Controller state drift against the engineering baseline

## Prepare

**Hypothesis.** If a controller was reconfigured the way the FBI describes, its current state diverges from the last approved
engineering baseline in at least one of five fields: password state, IP address, key-switch mode, fault history, or running program.
The attack leaves no host artifact, so the controller itself is the evidence - and only a comparison makes the evidence legible.

**Scope.** Every MicroLogix 1100/1400, CompactLogix and ControlLogix controller in the fleet, not only the one that misbehaved.
The July 2026 wave hit sites in parallel, and one victim only found modified logic after comparing ladder logic across several sites.

**Prerequisite.** An approved offline copy of every project, hashed, with a date. If it does not exist, create it now on a healthy
plant and treat that as the deliverable of this hunt's first iteration.

## Execute

1. **Read-only inventory.** From an engineering workstation on the OT cell, enumerate identity, mode, fault and program metadata for
   each controller with RSLinx Classic or an equivalent read-only client. Record: product code, firmware revision, serial, IP,
   subnet, gateway, key-switch position, fault code, and program name and checksum.
2. **Compare against baseline.**

```powershell
# Hash every approved project copy and every recently touched project artifact, then diff the two sets
$approved = Get-ChildItem '<add_known_project_repository_path>' -Recurse -Include *.RSS,*.ACD,*.L5X |
  ForEach-Object { [pscustomobject]@{ Name=$_.Name; Sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash } }
$staged = Get-ChildItem C:\Users -Recurse -Include *.RSS,*.ACD,*.L5X -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Name=$_.Name; Sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash; Path=$_.FullName } }
Compare-Object $approved $staged -Property Name,Sha256 | Sort-Object Name
```

3. **Ladder logic diff.** For every controller whose checksum differs, export the running program and diff it against the approved
   copy: rungs, Add-On Instructions and function blocks, alarm logic, shutdown and interlock logic, I/O configuration, and any
   reusable code module. The AA26-097A pattern - logic that keeps downstream indications looking normal while overriding the
   instructions that hold safe operating parameters - is invisible in a checksum summary and obvious in a rung-level diff.
4. **Cross-site correlation.** Line up the drift findings by site and by integrator. Identical drift at two sites of the same
   integrator is a fleet compromise; drift at one site is an incident.

## Act

- **Signal.** A password where none was configured, an IP outside the documented plan, a key switch left in REMOTE or PROGRAM, an
  unexplained fault or restart, or a program checksum with no matching change record.
- **Noise.** Legitimate commissioning and maintenance produce all five. Every one of them should have a change ticket; the absence
  of the ticket is what makes the drift a finding.
- **Escalate when.** Drift correlates in time with an external session found in hunt H1, or when the same drift appears at more than
  one site.
- **Product.** A hashed baseline register per controller, a documented drift report, and - where drift is confirmed - recovery via
  Rockwell advisory SD1790 with the program restored from a validated copy, never from a post-incident backup.
