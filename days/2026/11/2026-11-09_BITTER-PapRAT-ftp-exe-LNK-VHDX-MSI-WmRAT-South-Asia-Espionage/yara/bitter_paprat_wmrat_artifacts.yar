/*
   BITTER (TA397) PapRAT campaign - ftp.exe .ico "script" files and PapRAT PE artefacts
   Author: Jarmi
   Date: 2026-11-09
   Reference: FortiGuard Labs (Fortinet) 2026-11-02 "BITTER expands its arsenal with PapRAT"
              https://www.fortinet.com/blog/threat-research
   Honesty: derived from secondary reports of the FortiGuard Labs (Fortinet) 2026-11-02 research as
   relayed by Infosecurity Magazine, GBHackers, Hackread, Cyberpress, SOC Prime, OffSeq/OTX; the
   primary Fortinet blog was not read; no first-hand sample analysis. Strings are the literals quoted
   in those reports and were NOT verified against samples. The Rust build stores strings reversed +
   ROT-3 and the C++ build XOR-encodes C2 data with key 0x50, so plaintext C2 strings may be absent;
   the PE rule therefore leans on PDB / product / masquerade names and command-code clusters.
   Indicators decay; re-packed variants will evade.
   Scan targets: user profile and Public folders, mounted VHDX images, extracted RAR / MSI Binary
   tables, sandbox drops.
   Reference hashes (roles unpublished except the two LNKs; NOT used in conditions):
     LNK a3081df333ca7f18bd90d10a45125ab5011dcf9d2806feae2935f09cab07da4c
     LNK e3992f8c945b0761242377cba32d91b0a390c7cecd79478439843d93e6d2b76b
     ccefbdec2718d864d9d33c743aabfcef88a8d7904d1c598bfcf15cf5f3591c88
     411c0b9a2f98b927d806a685faf0c1ab1005647b4816157008892347fb88546b
     569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33
*/

rule BITTER_FtpExe_Ico_Script_Or_LNK
{
    meta:
        author = "Jarmi"
        description = "Text-based .ico 'script' or LNK used in the BITTER ftp.exe chain: ftp bang shell escape (!more / !cmd) referencing res.ico or icon.ico, or a script combining curl with the err.log / abc.pdf staging names, a schtasks update masquerade or the fake 'Explorer was unable to open this file!' error"
        date = "2026-11-09"
        reference = "https://www.fortinet.com/blog/threat-research"
        confidence = "low"
        family = "BITTER-ftp-ico-downloader"
    strings:
        $bang_more = "!more" ascii wide nocase
        $bang_cmd = "!cmd" ascii wide nocase
        $ico_res = "res.ico" ascii wide nocase
        $ico_icon = "icon.ico" ascii wide nocase
        $ftp = "ftp.exe" ascii wide nocase
        $curl = "curl" ascii wide nocase
        $errlog = "err.log" ascii wide nocase
        $abcpdf = "abc.pdf" ascii wide nocase
        $schtasks = "schtasks" ascii wide nocase
        $fake_err = "Explorer was unable to open this file!" ascii wide
    condition:
        filesize < 2MB and
        uint16(0) != 0x5A4D and
        (
            (($bang_more or $bang_cmd) and ($ico_res or $ico_icon)) or
            ($ftp and ($ico_res or $ico_icon)) or
            ($curl and ($errlog or $abcpdf) and ($schtasks or $fake_err)) or
            ($fake_err and $curl)
        )
}

rule BITTER_PapRAT_PE
{
    meta:
        author = "Jarmi"
        description = "PapRAT (BITTER / TA397) PE: Rust build PDB requpap.pdb / product papsolutions, C++ build bruzsvc.exe masquerade with Microsoft version resource, or the PapRAT three-letter command-code cluster (FDD, GDR, SS1, UPP, DWW, MS2, SLP, BYE)"
        date = "2026-11-09"
        reference = "https://www.fortinet.com/blog/threat-research"
        confidence = "medium"
        family = "PapRAT"
    strings:
        $pdb = "requpap.pdb" ascii nocase
        $prod_a = "papsolutions" ascii nocase
        $prod_w = "papsolutions" wide nocase
        $bruz_a = "bruzsvc" ascii nocase
        $bruz_w = "bruzsvc" wide nocase
        $ms_corp = "Microsoft Corporation" wide
        $ms_redist = "Microsoft redistributables" wide nocase
        $vnces = "vnces.exe" ascii wide nocase
        $c_fdd = "FDD" ascii fullword
        $c_gdr = "GDR" ascii fullword
        $c_ss1 = "SS1" ascii fullword
        $c_upp = "UPP" ascii fullword
        $c_dww = "DWW" ascii fullword
        $c_ms2 = "MS2" ascii fullword
        $c_slp = "SLP" ascii fullword
        $c_bye = "BYE" ascii fullword
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and
        (
            $pdb or
            ($prod_a or $prod_w) or
            (($bruz_a or $bruz_w) and ($ms_corp or $ms_redist)) or
            ($vnces and ($bruz_a or $bruz_w or $c_dww)) or
            ($c_fdd and $c_gdr and $c_ss1 and $c_upp and $c_dww) or
            ($c_ms2 and $c_slp and $c_bye and ($c_fdd or $c_gdr or $c_ss1 or $c_upp or $c_dww))
        )
}
