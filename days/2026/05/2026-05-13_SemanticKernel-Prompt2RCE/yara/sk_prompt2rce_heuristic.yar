/*
   YARA — Semantic Kernel prompt-to-RCE heuristics (CVE-2026-26030 + CVE-2026-25592)
   Author:      Jarmi
   Date:        2026-05-13
   Reference:   https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

   Two complementary rules:
     SK_PromptInjection_AST_Traversal_Heuristic_2026 — catches the canonical
       Python AST-traversal escape used to bypass the InMemoryVectorStore
       filter validator. Useful when scanning chat transcripts, RAG corpora,
       log dumps, ingest queues, prompt-snapshot exports, or exfilled session
       bundles for CVE-2026-26030 exploit attempts.

     SK_SessionsPython_SandboxEscape_Heuristic_2026 — catches the canonical
       sandbox-escape primitive of CVE-2026-25592: DownloadFileAsync invoked
       by the model pointing at the Windows Startup folder.
*/

rule SK_PromptInjection_AST_Traversal_Heuristic_2026
{
    meta:
        author       = "Jarmi"
        description  = "Catches Python AST-traversal escape patterns used to bypass Semantic Kernel InMemoryVectorStore filter eval (CVE-2026-26030)"
        date         = "2026-05-13"
        reference    = "https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/"
        confidence   = "medium"
        family       = "CVE-2026-26030"

    strings:
        // AST-traversal anchors
        $a1 = "().__class__.__bases__"            ascii wide nocase
        $a2 = "__subclasses__()"                  ascii wide
        $a3 = "BuiltinImporter"                   ascii wide
        $a4 = ".load_module("                     ascii wide
        $a5 = "__class__.__mro__"                 ascii wide

        // Exec primitives commonly chained after traversal
        $e1 = "os.system("                        ascii wide nocase
        $e2 = "subprocess.Popen("                 ascii wide nocase
        $e3 = "os.popen("                         ascii wide nocase

        // Lambda template anchor (default filter shape)
        $l1 = "lambda x: x."                      ascii wide

    condition:
        filesize < 4MB and
        (
            (2 of ($a*) and 1 of ($e*)) or
            (2 of ($a*) and $l1)
        )
}

rule SK_SessionsPython_SandboxEscape_Heuristic_2026
{
    meta:
        author       = "Jarmi"
        description  = "Catches Semantic Kernel SessionsPythonPlugin DownloadFileAsync invocation targeting the Windows Startup folder (CVE-2026-25592)"
        date         = "2026-05-13"
        reference    = "https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/"
        confidence   = "high"
        family       = "CVE-2026-25592"

    strings:
        $tool1 = "DownloadFileAsync"              ascii wide
        $tool2 = "UploadFileAsync"                ascii wide
        $plug  = "SessionsPythonPlugin"           ascii wide

        $sink1 = "Start Menu\\Programs\\Startup"  ascii wide
        $sink2 = "Start Menu/Programs/Startup"    ascii wide
        $sink3 = "Microsoft\\Windows\\Start Menu" ascii wide

    condition:
        filesize < 4MB and
        (
            ($tool1 and (1 of ($sink*))) or
            ($plug  and (1 of ($sink*))) or
            ($tool2 and $plug)
        )
}
