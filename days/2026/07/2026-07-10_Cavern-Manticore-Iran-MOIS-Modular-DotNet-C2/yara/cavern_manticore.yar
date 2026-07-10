/*
   Cavern Manticore (Iran-MOIS) - Cavern / Cav3rn modular .NET C2 framework
   Author: Jarmi
   Date:   2026-07-10
   Reference: https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
   Note:   String/structure anchors for the Cavern agent, its post-exploitation modules, and the
           IIS webshell relay. Samples span three .NET compilation formats (.NET Framework,
           Mixed-Mode C++/CLI, Native AOT) and are near-zero-detection and per-victim, so these
           rules target durable naming/interface strings, not a single build. Tune filesize and
           remove rules that do not fit your data source. Full SHA256 set is in iocs.csv.
*/

rule Cavern_Manticore_Agent
{
    meta:
        author = "Jarmi"
        description = "Cavern Agent (uxtheme.dll) - module dispatcher naming and uniform interface strings"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        confidence = "medium"
        family = "CavernManticore"
    strings:
        $b1 = "CAV3RN" ascii wide
        $b2 = "Cav3rn" ascii wide
        $if = "get_version" ascii wide
        $mod = "n-HTCommp" ascii wide
    condition:
        filesize < 6MB and (($b1 or $b2) and ($if or $mod))
}

rule Cavern_Manticore_Modules
{
    meta:
        author = "Jarmi"
        description = "Cavern post-exploitation module naming convention (native n- DLLs and managed modules)"
        date = "2026-07-10"
        reference = "https://gbhackers.com/cavern-manticore-malware/"
        confidence = "low"
        family = "CavernManticore"
    strings:
        $m1 = "n-HTCommp.dll" ascii wide
        $m2 = "n-ten.dll" ascii wide
        $m3 = "n-sws.dll" ascii wide
        $m4 = "LdapBrute" ascii wide
    condition:
        filesize < 6MB and ($m1 or $m2 or $m3 or $m4)
}

rule Cavern_Manticore_IIS_Webshell
{
    meta:
        author = "Jarmi"
        description = "Cavern IIS relay handler - CAV3RN_Http_Module / cac.aspx webshell-style transport"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        confidence = "medium"
        family = "CavernManticore"
    strings:
        $h1 = "CAV3RN_Http_Module" ascii wide
        $h2 = "cac.aspx" ascii wide
    condition:
        filesize < 1MB and ($h1 or $h2)
}
