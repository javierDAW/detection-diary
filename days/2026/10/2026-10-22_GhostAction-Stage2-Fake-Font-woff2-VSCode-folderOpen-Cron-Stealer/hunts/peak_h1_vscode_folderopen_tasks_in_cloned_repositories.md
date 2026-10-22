# PEAK hunt H1 - VS Code tasks that run on folder open in repositories developers cloned

## Prepare

**Hypothesis.** If a repository we cloned contains a `.vscode/tasks.json` with `runOn: folderOpen`, the first time a developer trusts the workspace the task runs code with no click on a build button. GhostAction stage 2 and the Contagious Interview Fake Font lures both rely on this to start a JavaScript file hidden behind a font name.

**Why first.** The task file is plain JSON, easy to find in bulk, and it is the one artifact common to the 2026 campaigns. It exists before any malware runs.

**Scope.** Developer workstations, build agents with an editor, and every repository an engineer has cloned in the last 30 days, including third-party and recruiter-supplied code.

**Data quality check first.** Confirm that file-creation telemetry for `.vscode` folders is collected, and that you can list local clones (EDR file inventory or a script run through your management tool).

## Execute

```bash
# Author: Jarmi
# List every tasks.json under a source directory that contains a folderOpen trigger, with the command it runs.
find "$HOME" -path '*/.vscode/tasks.json' -not -path '*/node_modules/*' 2>/dev/null \
 | while read -r f; do grep -l 'folderOpen' "$f" >/dev/null 2>&1 && { echo "== $f"; grep -nE '"(command|args|label|runOn|reveal)"' "$f"; }; done
```

```powershell
# Author: Jarmi
# Windows: find tasks.json files with folderOpen under the user profile and show matching lines.
Get-ChildItem -Path $env:USERPROFILE -Recurse -Filter tasks.json -ErrorAction SilentlyContinue |
  Where-Object { $_.DirectoryName -like '*\.vscode' } |
  Select-String -Pattern 'folderOpen','woff2','"node"' | Select-Object Path, LineNumber, Line
```

## Act

1. For each hit, read the command. A task that runs node, a shell or a downloaded file with `reveal: never` needs an owner explanation.
2. If the target is a `.woff2`, `.png` or other non-script file, treat the device as suspect and go to H2.
3. Check VS Code workspace trust history on the machine and whether `task.allowAutomaticTasks` is `on`.
4. Ask the developer where the repository came from (recruiter, take-home test, forked project).

## Knowledge

- Many legitimate repositories use folderOpen for watchers or linters; allow-list repositories you own.
- The user must trust the workspace for the task to run; Restricted Mode blocks it.
- Cursor and other VS Code forks honour the same file.
