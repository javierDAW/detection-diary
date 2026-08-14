/*
   YARA rules for Lazarus Operation Dream Job 2026 (AFD.sys zero-day wave)
   Author: Jarmi
   Scope: the trojanized SecurityPDF viewer, its marker-gated payload, and Troy
   backdoor / SecurityPDF binaries that embed the Enveil-impersonation C2 domains.
   These are content signatures on public IOCs, not a substitute for the hash set
   in iocs.csv. Bounded by filesize. See Check Point Research 2026-08-12.
*/

rule Lazarus_DreamJob_SecurityPDF_Marker
{
    meta:
        author = "Jarmi"
        description = "Trojanized SecurityPDF viewer / marked PDF carrying the sumatrapdf encryption marker that gates decryption and execution of the embedded Troy payload."
        date = "2026-08-14"
        reference = "https://thehackernews.com/2026/08/lazarus-exploits-windows-zero-day-to.html"
        confidence = "high"
        family = "Lazarus.DreamJob.SecurityPDF"
    strings:
        $marker = "This document is encrypted with sumatrapdf reader!!!!!!!!!!!!" ascii wide
        $pdf    = "%PDF-" ascii
        $mupdf  = "MuPDF" ascii wide
    condition:
        filesize < 30MB and ( $marker or ( $pdf and $mupdf and $marker ) )
}

rule Lazarus_DreamJob_C2_Domains_In_PE
{
    meta:
        author = "Jarmi"
        description = "PE embedding one or more of the Lazarus Dream Job Enveil-impersonation C2 domains (Troy / SecurityPDF)."
        date = "2026-08-14"
        reference = "https://cybersecuritynews.com/windows-afd-sys-zero-day-exploited/"
        confidence = "medium"
        family = "Lazarus.DreamJob.Troy"
    strings:
        $mz  = { 4D 5A }
        $d1  = "envell.xyz" ascii wide nocase
        $d2  = "enveil.online" ascii wide nocase
        $d3  = "uxtramine.org" ascii wide nocase
    condition:
        $mz at 0 and filesize < 8MB and ( $d1 or $d2 or $d3 )
}
