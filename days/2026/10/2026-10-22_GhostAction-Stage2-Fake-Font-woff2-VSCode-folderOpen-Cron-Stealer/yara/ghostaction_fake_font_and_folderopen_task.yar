/*
  Title: GhostAction stage 2 - JavaScript hidden in a .woff2 file and a VS Code folderOpen task that launches it
  Author: Jarmi
  Date: 2026-10-22
  Reference: https://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html
  Scope: files in a cloned repository (public/fonts/*.woff2, .vscode/tasks.json). No public sample or hash exists for the stage 2 payload, so the
  rules describe the technique, not a known file, and were not run against a real sample. Rule 1 looks for a file named like a font whose header is
  not the WOFF2 magic and that contains JavaScript tokens. Rule 2 looks for a tasks.json that auto-runs node on a .woff2 path.
*/

rule GhostAction_Fake_Font_JavaScript_Payload
{
    meta:
        author = "Jarmi"
        description = "File that is not a WOFF2 font (header is not wOF2) but contains JavaScript loader tokens, as in the fake fa-solid-400.woff2 payload"
        date = "2026-10-22"
        reference = "https://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html"
        confidence = "low"
        family = "GhostAction-stage2-fake-font"
    strings:
        $js1 = "require(" ascii
        $js2 = "child_process" ascii
        $js3 = "process.platform" ascii
        $js4 = "crontab" ascii
        $js5 = "XMLHttpRequest" ascii
        $js6 = "http.request" ascii
        $js7 = "fs.readFileSync" ascii
    condition:
        filesize < 2MB and uint32be(0) != 0x774F4632 and ($js1 and ($js2 or $js4 or $js5 or $js6 or $js7 or $js3))
}

rule GhostAction_VSCode_FolderOpen_Task_Runs_Font_File
{
    meta:
        author = "Jarmi"
        description = "VS Code tasks.json that runs node on a .woff2 path when the folder is opened (runOn folderOpen)"
        date = "2026-10-22"
        reference = "https://www.webpronews.com/vs-code-tasks-become-silent-killers-in-fresh-npm-and-go-package-hijacks/"
        confidence = "medium"
        family = "GhostAction-stage2-fake-font"
    strings:
        $run = "folderOpen" ascii
        $runon = "runOn" ascii
        $node = "node" ascii
        $font = ".woff2" ascii
    condition:
        filesize < 64KB and $runon and $run and $node and $font
}
