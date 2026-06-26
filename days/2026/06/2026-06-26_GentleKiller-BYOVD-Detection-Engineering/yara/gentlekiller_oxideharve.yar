/*
 * YARA rules for GentleKiller BYOVD EDR-killer suite and OxideHarvest credential stealer
 * Cluster: The Gentlemen RaaS — operator-maintained EDR-killer portfolio
 * Source:  ESET Research 2026-06-18 "Killing me gently: Inside Gentlemen's EDR killer framework"
 * Author:  Jarmi
 * Date:    2026-06-26
 * Reference: https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
 */

rule GentleKiller_Process_Termination_Target_List
{
    meta:
        author      = "Jarmi"
        description = "Detects GentleKiller EDR-killer by its embedded security-product process termination target list — shared across all 8+ variants regardless of packer or driver. The process names are present in the binary as wide strings used for loop-based process killing."
        date        = "2026-06-26"
        reference   = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        confidence  = "high"
        family      = "GentleKiller"

    strings:
        // Core EDR targets present across all GentleKiller variants
        $proc1  = "MsMpEng.exe" ascii wide nocase
        $proc2  = "CSFalconService.exe" ascii wide nocase
        $proc3  = "SentinelAgent.exe" ascii wide nocase
        $proc4  = "SophosHealth.exe" ascii wide nocase
        $proc5  = "ekrn.exe" ascii wide nocase
        $proc6  = "bdagent.exe" ascii wide nocase
        $proc7  = "HuntressAgent.exe" ascii wide nocase
        // Staging directory anchor
        $stage  = "GentlemenCollection" ascii wide
        // Console output string (from ESET Figure 1 — GentleKiller output window)
        $out1   = "Killing" ascii wide
        $out2   = "processes" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $stage and
        (
            (3 of ($proc1, $proc2, $proc3, $proc4, $proc5, $proc6, $proc7))
            or ($out1 and $out2 and 2 of ($proc1, $proc2, $proc3, $proc4, $proc5, $proc6, $proc7))
        )
}


rule GentleKiller_Impersonation_Layer
{
    meta:
        author      = "Jarmi"
        description = "Detects GentleKiller binaries using Gentlemen's impersonation evasion layer: invalid digital signature copied from a legitimate security vendor combined with a high-entropy body (Enigma/Themida packed). Broad rule — tune with PE version info checks. Works against all 11 tools in the suite (GentleKiller variants + HexKiller + ThrottleBlood + HavocKiller)."
        date        = "2026-06-26"
        reference   = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        confidence  = "medium"
        family      = "GentleKiller"

    strings:
        // Vendor names used for impersonation in GentleKiller filenames / version info
        $imp1 = "Kaspersky" ascii wide nocase
        $imp2 = "Valorant" ascii wide nocase
        $imp3 = "FaceIT" ascii wide nocase
        $imp4 = "WatchDog" ascii wide nocase
        $imp5 = "Symantec" ascii wide nocase
        // Enigma packer marker (section name)
        $enigma = ".enigma" ascii
        // Themida packer markers
        $themida1 = ".themida" ascii
        $themida2 = "Themida" ascii
        // Security process targets confirming EDR-kill intent
        $edr1 = "MsSense.exe" ascii wide nocase
        $edr2 = "SentinelServiceHost.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        ($enigma or $themida1 or $themida2) and
        1 of ($imp1, $imp2, $imp3, $imp4, $imp5) and
        1 of ($edr1, $edr2)
}


rule OxideHarvest_Rust_Credential_Stealer
{
    meta:
        author      = "Jarmi"
        description = "Detects OxideHarvest, a Rust-based credential stealer used by Gentlemen affiliate 'quant' (alias buildx641). OxideHarvest exfiltrates browser credentials from Chromium and Gecko browser profiles. The embedded JSON config containing browser path strings is a durable anchor that survives recompilation."
        date        = "2026-06-26"
        reference   = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        confidence  = "high"
        family      = "OxideHarvest"

    strings:
        // Embedded JSON config paths from ESET report (Rust binary, unobfuscated in most builds)
        $cfg1  = "chronium_browsers" ascii
        $cfg2  = "gecko_browsers" ascii
        $cfg3  = "\\Google\\Chrome\\User Data" ascii wide
        $cfg4  = "\\Microsoft\\Edge\\User Data" ascii wide
        $cfg5  = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $cfg6  = "\\Mozilla\\Firefox\\Profiles\\" ascii wide
        // CLI argument strings used by OxideHarvest
        $arg1  = "-i" ascii
        $arg2  = "-u" ascii
        $arg3  = "-p" ascii
        $arg4  = "-t" ascii
        $arg5  = "-o" ascii
        // Rust panic handler string typical of Rust binaries
        $rust  = "panicked at" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        $rust and
        ($cfg1 or $cfg2) and
        2 of ($cfg3, $cfg4, $cfg5, $cfg6) and
        3 of ($arg1, $arg2, $arg3, $arg4, $arg5)
}
