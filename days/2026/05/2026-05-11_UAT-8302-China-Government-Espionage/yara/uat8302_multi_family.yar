/*
   UAT-8302 multi-family heuristic suite
   Author:      Jarmi
   Date:        2026-05-11
   Reference:   https://blog.talosintelligence.com/uat-8302/
   Coverage:    NetDraft / FringePorch (FinalDraft .NET port),
                CloudSorcerer v3 (process branching + dead-drop),
                SNOWLIGHT / SNOWRUST / VSHELL stagers (XOR 0x99 key).
   Confidence:  high for hash-bearing parents, medium for heuristics.
*/

rule UAT_8302_NetDraft_FringePorch_2026
{
    meta:
        author      = "Jarmi"
        description = "UAT-8302 NetDraft .NET implant with FringePorch helper library embedded via Fody/Costura, beaconing Microsoft Graph OneDrive C2"
        date        = "2026-05-11"
        reference   = "https://blog.talosintelligence.com/uat-8302/"
        confidence  = "high"
        family      = "NetDraft / NosyDoor / FinalDraft.NET"

    strings:
        $mz           = { 4D 5A }
        $clr          = "BSJB"
        $costura_a    = "Costura.Common" ascii wide
        $costura_b    = "Fody" ascii wide
        $netdraft_a   = "FringePorch" ascii wide
        $netdraft_b   = "NetDraft" ascii wide nocase
        $graph_a      = "graph.microsoft.com" ascii wide
        $graph_b      = "/me/drive/" ascii wide
        $graph_c      = "/cmd_queue/" ascii wide
        $plugin_run   = "Plugin.Run" ascii wide

    condition:
        $mz at 0
        and $clr
        and (
            (1 of ($costura_*) and 1 of ($netdraft_*))
            or (1 of ($graph_*) and $plugin_run)
        )
        and filesize < 12MB
}

rule UAT_8302_CloudSorcerer_v3_2026
{
    meta:
        author      = "Jarmi"
        description = "CloudSorcerer v3 — process-name branching dpapimig.exe / spoolsv.exe with named-pipe IPC and GitHub or GameSpot dead-drop resolver for C2 info"
        date        = "2026-05-11"
        reference   = "https://blog.talosintelligence.com/uat-8302/"
        confidence  = "high"
        family      = "CloudSorcerer"

    strings:
        $mz          = { 4D 5A }
        $proc_a      = "dpapimig.exe" ascii wide
        $proc_b      = "spoolsv.exe" ascii wide
        $proc_c      = "explorer.exe" ascii wide
        $pipe        = "\\\\.\\pipe\\" ascii wide
        $deaddrop_a  = "github.com" ascii wide
        $deaddrop_b  = "gamespot.com" ascii wide
        $dropbox     = "api.dropboxapi.com" ascii wide
        $onedrive    = "graph.microsoft.com" ascii wide

    condition:
        $mz at 0
        and 2 of ($proc_*)
        and $pipe
        and (1 of ($deaddrop_*) or $dropbox or $onedrive)
        and filesize < 4MB
}

rule UAT_8302_VSHELL_SNOWLIGHT_SNOWRUST_Stager_2026
{
    meta:
        author      = "Jarmi"
        description = "SNOWLIGHT or SNOWRUST stager fetching VSHELL final payload with single-byte XOR key 0x99 (Talos observation, also seen in UAT-6382)"
        date        = "2026-05-11"
        reference   = "https://blog.talosintelligence.com/uat-8302/"
        confidence  = "medium"
        family      = "SNOWLIGHT / SNOWRUST / VSHELL"

    strings:
        $mz          = { 4D 5A }
        $rust_a      = "panicked at" ascii
        $rust_b      = "rust_begin_unwind" ascii
        $lexicrypt   = "LexiCrypt" ascii wide
        $wininet     = "wininet.dll" ascii wide
        $xor99_a     = { 6A 99 ?? ?? ?? ?? 30 ?? 4? 75 }
        $xor99_b     = { B0 99 30 ?? 4? 75 }
        $vshell      = "vshell" ascii wide nocase
        $explorer    = "explorer.exe" ascii wide

    condition:
        $mz at 0
        and (
            (2 of ($rust_*) and ($lexicrypt or $wininet))
            or (1 of ($xor99_*) and $wininet and $explorer)
            or ($vshell and 1 of ($xor99_*))
        )
        and filesize < 8MB
}
